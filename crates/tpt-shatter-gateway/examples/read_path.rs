// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Drives the transport-neutral read path directly: a valid token, a token for another shard,
//! a forged token, an expired token, and a burst that hits the rate limit. Every outcome is a
//! `Response` with a stable status and code, and the access-log line never holds a secret.
//!
//! Run with: `cargo run -p tpt-shatter-gateway --example read_path`

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_shatter_common::{Record, Scope, Scopes, ShardKey, ShatterError};
use tpt_shatter_gateway::{Gateway, RateLimiter};
use tpt_shatter_token::Signer;

/// Synthetic store: one record, held for one shard. A real source would call the assembler.
const KNOWN_SHARD: [u8; 32] = [0x42; 32];

fn source(shard: &ShardKey) -> Result<Record, ShatterError> {
    if shard.as_bytes() != &KNOWN_SHARD {
        return Err(ShatterError::Unauthorized);
    }
    let mut record = Record::new();
    record.insert("name", "Synthetic Person");
    record.insert("birth_year", "1994");
    Ok(record)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Arc::new(RwLock::new(Signer::new(1, [0x11; 32])));

    // Rate limit per token: 3 requests in a burst, refilling at 1 per second.
    let limiter = RateLimiter::new(3, 1, 1_000)?;
    let gateway = Gateway::new(Arc::clone(&signer), source, limiter);

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let now_ms = now * 1_000;
    let shard = ShardKey::from_bytes(KNOWN_SHARD);
    let shard_hex = hex(shard.as_bytes());

    // A read token for the known shard.
    let token = signer.read().map_err(|_| "signer lock poisoned")?.issue(
        &shard,
        Scopes::from_scopes(&[Scope::Read]),
        now,
    )?;

    // 1. The happy path. The response carries the fields, and `200 ok`.
    let ok = gateway.read(token.as_str(), &shard_hex, now_ms);
    print_response("valid token, known shard", &ok);

    // 2. A token bound to a different shard is refused with the same code as a forgery.
    let other = ShardKey::from_bytes([0x43; 32]);
    let wrong_shard_token = signer.read().map_err(|_| "signer lock poisoned")?.issue(
        &other,
        Scopes::from_scopes(&[Scope::Read]),
        now,
    )?;
    let wrong = gateway.read(wrong_shard_token.as_str(), &shard_hex, now_ms + 1);
    print_response("token for another shard", &wrong);

    // 3. A forged token is refused. Callers cannot tell forgery from expiry or wrong scope.
    let forged = gateway.read("not-a-real-token", &shard_hex, now_ms + 2);
    print_response("forged token", &forged);

    // 4. A token expires. Once its lifetime has passed, the same token stops working.
    let expired = gateway.read(token.as_str(), &shard_hex, now_ms + 120_000);
    print_response("token after expiry", &expired);

    // 5. A burst past the limit is refused with 429 before the token is even checked.
    for attempt in 0..4 {
        let r = gateway.read(token.as_str(), &shard_hex, now_ms + 3);
        print_response(&format!("burst request {attempt}"), &r);
    }

    // Access-log lines carry the status, code, a hash of the token, and a field count.
    // They never include the token itself or any field value.
    println!("access log sample: {}", ok.access_log_line());
    Ok(())
}

fn print_response(label: &str, r: &tpt_shatter_gateway::Response) {
    println!(
        "{label}: {} {} (fields: {})",
        r.status,
        r.code,
        r.fields.len()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
