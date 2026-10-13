// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Issues a capability token for one shard, checks it against the shard and scope it
//! should grant, shows expiry, and rotates the signing key to invalidate everything.
//!
//! Run with: `cargo run -p tpt-shatter-token --example issue_and_authorize`

use tpt_shatter_common::{Scope, Scopes, ShardKey, ShatterError};
use tpt_shatter_token::{MAX_TTL_SECS, Signer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The signer holds a 256-bit key. In a real node the key comes from the environment
    // or a secret store and is never written to disk. Here it is fixed for the example.
    let mut signer = Signer::new(1, [0x11; 32]);

    // "now" is passed in as Unix seconds, so tests and replays are deterministic.
    let now: u64 = 1_700_000_000;
    let shard = ShardKey::from_bytes([0x42; 32]);

    // Grant read-only access, and only for this shard, for 30 seconds.
    let read_only = Scopes::from_scopes(&[Scope::Read]);
    let token = signer.issue_with_ttl(&shard, read_only, now, 30)?;
    println!("issued token of {} characters", token.len());

    // The token is a bearer secret. Pass it to the caller, and never log it.
    // Verifying it checks the signature, the key version, and the expiry time.
    let claims = signer.verify(&token, now + 1)?;
    println!("token expires at {}", claims.expires_at());

    // Authorization checks three things: the shard binding, the scope, and the signature.
    signer.authorize(&token, &shard, Scope::Read, now + 1)?;
    println!("read on the bound shard: allowed");

    // A different shard is refused, even with a valid token.
    let other_shard = ShardKey::from_bytes([0x43; 32]);
    report(
        "read on another shard",
        signer.authorize(&token, &other_shard, Scope::Read, now + 1),
    );

    // A scope the token does not grant is refused.
    report(
        "delete on the bound shard",
        signer.authorize(&token, &shard, Scope::Delete, now + 1),
    );

    // Tokens expire strictly. At the expiry time the token is dead.
    report(
        "read after expiry",
        signer.authorize(&token, &shard, Scope::Read, now + 30),
    );

    // The TTL is capped. Longer lifetimes are refused outright.
    let too_long = signer.issue_with_ttl(&shard, read_only, now, MAX_TTL_SECS + 1);
    println!("TTL above {MAX_TTL_SECS}s refused: {}", too_long.is_err());

    // Rotating the key invalidates every outstanding token immediately.
    let fresh = signer.issue_with_ttl(&shard, read_only, now, 30)?;
    signer.rotate(2, [0x22; 32]);
    report(
        "old token after rotation",
        signer.authorize(&fresh, &shard, Scope::Read, now + 1),
    );

    Ok(())
}

/// Prints the outcome of an authorization check. A refusal is expected in this example,
/// so it is printed rather than returned.
fn report(label: &str, outcome: Result<impl Sized, ShatterError>) {
    match outcome {
        Ok(_) => println!("{label}: allowed"),
        Err(e) => println!("{label}: refused ({e})"),
    }
}
