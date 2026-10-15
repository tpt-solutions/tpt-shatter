// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The assembler served over mTLS.
//!
//! The gateway sends a shard, and this service reassembles the record from the three vault
//! services and returns it. Only this service holds the derivation key, so a gateway host
//! never sees one. The gateway is the only client the server admits: the listener requires
//! a client certificate that chains to `client_ca`.
//!
//! [`AssemblerSource`] is the reassembly step. [`serve`] wraps any [`RecordSource`] in the
//! HTTP/1.1 protocol that [`tpt_shatter_gateway::remote::RemoteAssembler`] speaks.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use tpt_shatter_assembler::assemble_with_deadline;

pub mod canary;
pub use canary::{CanaryWatcher, LockedSource};
use tpt_shatter_common::{Record, ShardKey, ShatterError, ShatterSchema};
use tpt_shatter_gateway::RecordSource;
use tpt_shatter_gateway::remote::{RECORD_PATH, encode_error, encode_record};
use tpt_shatter_vault_client::Router;

/// Most connections served at once. Excess connections are dropped, not queued.
pub const MAX_CONNECTIONS: usize = 64;
/// How long a connection may stall on a read or write.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest request head the server reads. A record request is one short line.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Reassembles records from the vaults, holding the derivation key and the schema.
pub struct AssemblerSource {
    schema: Arc<ShatterSchema>,
    router: Arc<Router>,
    derivation: [u8; 32],
    deadline: Duration,
}

impl AssemblerSource {
    /// Creates a source. `deadline` bounds one reassembly; a vault still outstanding at the
    /// deadline fails the read, and no partial record is returned.
    #[must_use]
    pub fn new(
        schema: Arc<ShatterSchema>,
        router: Arc<Router>,
        derivation: [u8; 32],
        deadline: Duration,
    ) -> Self {
        Self {
            schema,
            router,
            derivation,
            deadline,
        }
    }
}

impl RecordSource for AssemblerSource {
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        assemble_with_deadline(
            &self.schema,
            &self.router,
            &self.derivation,
            shard,
            self.deadline,
        )
    }
}

/// Serves `source` on `listener` until the listener fails. Each connection is handled on its
/// own thread, up to [`MAX_CONNECTIONS`] at a time.
pub fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    source: Arc<dyn RecordSource>,
) -> Result<(), ShatterError> {
    let live = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let Ok(tcp) = connection else { continue };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (tls, source, live) = (Arc::clone(&tls), Arc::clone(&source), Arc::clone(&live));
        thread::spawn(move || {
            let _ = handle(tcp, tls, source.as_ref());
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(
    tcp: TcpStream,
    tls: Arc<ServerConfig>,
    source: &dyn RecordSource,
) -> Result<(), ShatterError> {
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let conn = ServerConnection::new(tls).map_err(|_| ShatterError::Internal)?;
    let mut stream = StreamOwned::new(conn, tcp);
    let (status, body) = match read_head(&mut stream) {
        Ok(head) => route(source, &head),
        Err(_) => bad_request(),
    };
    write_response(&mut stream, status, &body)
}

/// Reads the request head, through the blank line that ends it. The body is not read: every
/// request this service accepts has none.
fn read_head<S: Read>(stream: &mut S) -> Result<String, ShatterError> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(ShatterError::InvalidParameter);
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return Err(ShatterError::InvalidParameter),
        }
    }
    String::from_utf8(head).map_err(|_| ShatterError::InvalidParameter)
}

/// Answers one request head. Only `GET {RECORD_PATH}{shard}` over HTTP/1.1 is served.
fn route(source: &dyn RecordSource, head: &str) -> (u16, Vec<u8>) {
    let request_line = head.split("\r\n").next().unwrap_or("");
    let parts: Vec<&str> = request_line.split(' ').collect();
    let [method, path, version] = parts.as_slice() else {
        return bad_request();
    };
    if *method != "GET" || *version != "HTTP/1.1" {
        return bad_request();
    }
    let Some(hex) = path.strip_prefix(RECORD_PATH) else {
        return (404, br#"{"error":"not_found"}"#.to_vec());
    };
    let shard = match ShardKey::from_hex(hex) {
        Ok(shard) => shard,
        Err(error) => return encode_error(error),
    };
    match source.fetch(&shard) {
        Ok(record) => (200, encode_record(&record)),
        Err(error) => encode_error(error),
    }
}

fn write_response(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    status: u16,
    body: &[u8],
) -> Result<(), ShatterError> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Service Unavailable",
    };
    let head = [
        format!("HTTP/1.1 {status} {reason}"),
        "Content-Type: application/json".to_owned(),
        format!("Content-Length: {}", body.len()),
        "Cache-Control: no-store".to_owned(),
        "Connection: close".to_owned(),
        String::new(),
        String::new(),
    ]
    .join("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|_| ShatterError::Internal)?;
    // Send close_notify, so the client reads the end of the response as a clean close.
    stream.conn.send_close_notify();
    stream.flush().map_err(|_| ShatterError::Internal)
}

/// The answer to a request this service cannot parse.
fn bad_request() -> (u16, Vec<u8>) {
    (400, br#"{"error":"bad_request"}"#.to_vec())
}
