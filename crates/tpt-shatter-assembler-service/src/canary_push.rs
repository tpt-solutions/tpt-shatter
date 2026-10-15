// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The assembler's canary list listener. The node pushes each epoch's canary list here over
//! mTLS, and this listener writes it where [`crate::CanaryWatcher`] reads it.
//!
//! The listener requires a client certificate that chains to its `client_ca`, so only the
//! node can push. A list older than the one on disk is refused, so a replayed push cannot roll
//! the canaries back. The file is written atomically, so the watcher never reads half a list.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use tpt_shatter_canary::CanaryIds;
use tpt_shatter_common::ShatterError;
use tpt_shatter_gateway::remote::CANARY_IDS_PATH;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Room for the largest list `CanaryIds` accepts, with its header lines.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Serves list pushes on `listener` until the listener fails, writing each accepted list to
/// `list`. Pushes are handled one at a time. The node sends one per monitor pass.
pub fn serve_canary_list(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    list: PathBuf,
) -> Result<(), ShatterError> {
    for connection in listener.incoming() {
        let Ok(tcp) = connection else { continue };
        let _ = handle(tcp, Arc::clone(&tls), &list);
    }
    Ok(())
}

fn handle(tcp: TcpStream, tls: Arc<ServerConfig>, list: &Path) -> Result<(), ShatterError> {
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let conn = ServerConnection::new(tls).map_err(|_| ShatterError::Internal)?;
    let mut stream = StreamOwned::new(conn, tcp);
    let status = match read_body(&mut stream) {
        Ok(body) => apply(&body, list),
        Err(_) => 400,
    };
    write_status(&mut stream, status)
}

/// Writes the list in `body` to `list`, unless it is older than the one already there. Returns
/// the status to answer with: 204 when written, 409 when older, 400 when malformed, and 500
/// when the held list cannot be read or the write fails. A held list that cannot be read is
/// not overwritten.
fn apply(body: &[u8], list: &Path) -> u16 {
    let Ok(text) = std::str::from_utf8(body) else {
        return 400;
    };
    let Ok(incoming) = CanaryIds::parse(text) else {
        return 400;
    };
    if list.exists() {
        let Ok(held) = CanaryIds::read_file(list) else {
            return 500;
        };
        if incoming.epoch() < held.epoch() {
            return 409;
        }
    }
    match incoming.write_file(list) {
        Ok(()) => 204,
        Err(_) => 500,
    }
}

/// Reads one `POST` request and returns its body. The head is capped, and the body must have a
/// `Content-Length` no larger than [`MAX_BODY_BYTES`].
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
    if request_line != format!("POST {CANARY_IDS_PATH} HTTP/1.1") {
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
