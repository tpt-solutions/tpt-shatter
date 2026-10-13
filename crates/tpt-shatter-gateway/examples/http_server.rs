// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Serves the gateway over plain HTTP/1.1 on a local port, then makes one authorized request
//! and one unauthorized request against it, and exits. The client side is a raw TCP socket so
//! the example needs no extra dependencies.
//!
//! Plain HTTP is for local development only. Production uses `serve_tls` with TLS 1.3, which
//! is shown in the README.
//!
//! Run with: `cargo run -p tpt-shatter-gateway --example http_server`

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tpt_shatter_common::{Record, Scope, Scopes, ShardKey, ShatterError};
use tpt_shatter_gateway::{Gateway, HttpConfig, RateLimiter, Shared, serve};
use tpt_shatter_token::Signer;

const KNOWN_SHARD: [u8; 32] = [0x42; 32];

fn source(shard: &ShardKey) -> Result<Record, ShatterError> {
    if shard.as_bytes() != &KNOWN_SHARD {
        return Err(ShatterError::Unauthorized);
    }
    let mut record = Record::new();
    record.insert("name", "Synthetic Person");
    Ok(record)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Arc::new(RwLock::new(Signer::new(1, [0x11; 32])));
    let gateway = Gateway::new(
        Arc::clone(&signer),
        source,
        RateLimiter::new(20, 10, 1_000)?,
    );

    // The shared state is what every connection sees. Breaker flags feed /readyz. Access
    // lines go to stdout here. Writes are not offered, so the writer is `None` (405).
    let shared = Arc::new(Shared {
        gateway: Arc::new(gateway),
        breakers: Arc::new(|| vec![false, false, false]),
        access_log: Arc::new(|line| println!("access: {line}")),
        config: HttpConfig::default(),
        source_limiter: None,
        writer: None,
    });

    // Port 0 asks the OS for any free port, so the example never collides with another one.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        // `serve` runs until the listener fails. The example exits before that happens.
        let _ = serve(listener, shared).await;
    });
    println!("gateway listening on http://{addr}");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let shard = ShardKey::from_bytes(KNOWN_SHARD);
    let token = signer.read().map_err(|_| "signer lock poisoned")?.issue(
        &shard,
        Scopes::from_scopes(&[Scope::Read]),
        now,
    )?;

    // Health probes need no token.
    let health = request(
        addr,
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    println!("GET /healthz -> {}", status_line(&health));

    // An authorized read. The token travels in the Authorization header, never in the URL.
    let path = format!("/v1/records/{}", hex(&KNOWN_SHARD));
    let authorized = request(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            token.as_str()
        ),
    )
    .await?;
    println!("authorized read -> {}", status_line(&authorized));
    println!("body: {}", body(&authorized));

    // The same request with no token is refused.
    let anonymous = request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    println!("anonymous read -> {}", status_line(&anonymous));

    Ok(())
}

/// Sends one raw request and reads the whole response. Every request here asks for
/// `Connection: close`, so the response ends when the server closes the socket.
async fn request(addr: std::net::SocketAddr, raw: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(raw.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

fn body(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
