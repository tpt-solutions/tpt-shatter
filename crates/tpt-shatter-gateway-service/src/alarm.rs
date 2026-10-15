// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The gateway's alarm listener: installs a new token signing key pushed by the node.
//!
//! The listener requires a client certificate that chains to the alarm CA, so only the node
//! can reach it. It accepts a version only if it is newer than the one installed. A rotation
//! is written to the gateway's audit chain before the key changes, so a rotation that cannot
//! be recorded does not happen.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use tpt_shatter_common::{AuditAction, AuditEvent, AuditStore, ShatterError};
use tpt_shatter_gateway::remote::{ALARM_PATH, decode_rotation};
use tpt_shatter_token::Signer;

/// Most connections served at once. Excess connections are dropped, not queued.
pub const MAX_CONNECTIONS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// The largest body accepted. A rotation is one key and a version, far below this.
const MAX_BODY_BYTES: usize = 1024;
/// Digest fields for events that concern no token or shard.
const NO_DIGEST: [u8; 32] = [0; 32];

/// Serves rotation requests on `listener` until the listener fails.
pub fn serve_alarms(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    signer: Arc<RwLock<Signer>>,
    audit: Arc<AuditStore>,
) -> Result<(), ShatterError> {
    let live = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let Ok(tcp) = connection else { continue };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (tls, signer, audit, live) = (
            Arc::clone(&tls),
            Arc::clone(&signer),
            Arc::clone(&audit),
            Arc::clone(&live),
        );
        thread::spawn(move || {
            let _ = handle(tcp, tls, &signer, &audit);
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(
    tcp: TcpStream,
    tls: Arc<ServerConfig>,
    signer: &RwLock<Signer>,
    audit: &AuditStore,
) -> Result<(), ShatterError> {
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let conn = ServerConnection::new(tls).map_err(|_| ShatterError::Internal)?;
    let mut stream = StreamOwned::new(conn, tcp);
    let status = match read_body(&mut stream) {
        Ok(body) => apply(&body, signer, audit),
        Err(_) => 400,
    };
    write_status(&mut stream, status)
}

/// Installs the rotation in `body` if it is newer than the current key. Returns the status to
/// answer with: 204 when installed, 409 when stale, 400 when malformed, and 500 when the audit
/// record cannot be written (the key is then unchanged).
fn apply(body: &[u8], signer: &RwLock<Signer>, audit: &AuditStore) -> u16 {
    let Ok((version, key)) = decode_rotation(body) else {
        return 400;
    };
    let Ok(mut guard) = signer.write() else {
        return 500;
    };
    if version <= guard.key_version() {
        return 409;
    }
    let recorded = audit.record(AuditEvent {
        action: AuditAction::KeyRotation,
        token_digest: NO_DIGEST,
        shard_digest: NO_DIGEST,
        caller: None,
        vault: None,
        at: now_secs(),
    });
    if recorded.is_err() {
        return 500;
    }
    guard.rotate(version, key);
    204
}

/// Reads one `POST` request and returns its body. The head is capped, and the body must have
/// a `Content-Length` no larger than [`MAX_BODY_BYTES`].
fn read_body<S: Read>(stream: &mut S) -> Result<Vec<u8>, ShatterError> {
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
    let head = std::str::from_utf8(&head).map_err(|_| ShatterError::InvalidParameter)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ShatterError::InvalidParameter)?;
    if request_line != format!("POST {ALARM_PATH} HTTP/1.1") {
        return Err(ShatterError::InvalidParameter);
    }
    let length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or(ShatterError::InvalidParameter)?;
    if length > MAX_BODY_BYTES {
        return Err(ShatterError::InvalidParameter);
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|_| ShatterError::InvalidParameter)?;
    Ok(body)
}

fn write_status<S: Write>(stream: &mut S, status: u16) -> Result<(), ShatterError> {
    let reason = match status {
        204 => "No Content",
        400 => "Bad Request",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let head = [
        format!("HTTP/1.1 {status} {reason}"),
        "Content-Length: 0".to_owned(),
        "Cache-Control: no-store".to_owned(),
        "Connection: close".to_owned(),
        String::new(),
        String::new(),
    ]
    .join("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| ShatterError::Internal)
}

/// The current Unix time in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
