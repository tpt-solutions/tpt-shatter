// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Runs the token issuer in-process. A host application presents its caller secret and a
//! JSON request naming a shard and scopes. The issuer checks the caller's policy, appends the
//! issuance to a keyed audit chain, and only then returns the token. Several refusals are shown
//! too, since each is part of the policy.
//!
//! Run with: `cargo run -p tpt-shatter-node --example issue_token_request`

use std::fs;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tpt_shatter_node::{AuditStore, Issuer, IssuerConfig};
use tpt_shatter_token::Signer;

const CALLER_SECRET: &str = "example-caller-secret-from-the-host-app";
const SHARD_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // The signer that issues tokens is the same one the gateway verifies with.
    let signer = Arc::new(RwLock::new(Signer::new(1, [0x11; 32])));

    // Audit chain on disk. Every issuance is appended before its token is returned.
    let audit_path = std::env::temp_dir().join("tpt-shatter-example-issuer-audit.jsonl");
    let _ = fs::remove_file(&audit_path);
    let audit = Arc::new(AuditStore::open(&audit_path, [0x77; 32])?);

    // Callers are configured by the SHA-256 of their secret. The node never stores the secret.
    // The host application is allowed to read and nothing else. Tokens last at most 60 seconds,
    // whatever the request asks for.
    // The config is written as JSON, the same shape a node reads from its configuration file.
    let config: IssuerConfig = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1:0",
        "callers": [{
            "name": "host-app",
            "secret_sha256": sha256_hex(CALLER_SECRET),
            "scopes": ["read"],
            "max_ttl_secs": 60,
        }],
    }))?;
    let issuer = Issuer::new(Arc::clone(&signer), &config, Arc::clone(&audit))?;

    // 1. A valid request. The response holds the token and its expiry time.
    let body = format!(r#"{{"shard": "{SHARD_HEX}", "scopes": ["read"], "ttl_secs": 30}}"#);
    let ok = issuer.issue(CALLER_SECRET, body.as_bytes(), now);
    println!(
        "valid request: {} {} (caller: {:?})",
        ok.status, ok.code, ok.caller
    );
    let token = ok.body["token"]
        .as_str()
        .ok_or("no token in success body")?;
    println!("expires at {}", ok.body["expires_at"]);

    // The token verifies with the signer, as the gateway would check it.
    signer
        .read()
        .map_err(|_| "signer lock poisoned")?
        .verify(token, now)?;
    println!("gateway-side verification of the issued token: ok");

    // 2. Refusals. Each one is written so the caller learns nothing it should not.
    report(
        "wrong secret",
        issuer.issue("not-the-secret", body.as_bytes(), now),
    );
    report(
        "delete scope (never issuable)",
        issuer.issue(
            CALLER_SECRET,
            format!(r#"{{"shard": "{SHARD_HEX}", "scopes": ["delete"]}}"#).as_bytes(),
            now,
        ),
    );
    report(
        "write scope the caller does not hold",
        issuer.issue(
            CALLER_SECRET,
            format!(r#"{{"shard": "{SHARD_HEX}", "scopes": ["write"]}}"#).as_bytes(),
            now,
        ),
    );
    report(
        "TTL above the caller's maximum",
        issuer.issue(
            CALLER_SECRET,
            format!(r#"{{"shard": "{SHARD_HEX}", "scopes": ["read"], "ttl_secs": 3600}}"#)
                .as_bytes(),
            now,
        ),
    );
    report(
        "malformed JSON",
        issuer.issue(CALLER_SECRET, b"{not json", now),
    );

    // 3. Every successful issuance is in the chain. Refusals are not, because no token existed.
    let records = fs::read_to_string(&audit_path)?;
    println!("audit chain holds {} issuance(s)", records.lines().count());
    let _ = fs::remove_file(&audit_path);
    Ok(())
}

fn report(label: &str, outcome: tpt_shatter_node::IssueOutcome) {
    println!("{label}: {} {}", outcome.status, outcome.code);
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
