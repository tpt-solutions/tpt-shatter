// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The alarm listener: a node pushes a new token signing key over mTLS. Uses synthetic data only.

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use tpt_shatter_common::{AuditStore, Scope, Scopes, ShardKey, ShatterError};
use tpt_shatter_gateway::AlarmPeer;
use tpt_shatter_gateway::remote::client_config;
use tpt_shatter_gateway_service::{AUDIT_LOG, GatewayConfig, TOKEN_KEY_VERSION};
use tpt_shatter_token::Signer;

const ROTATED_KEY: [u8; 32] = [0x72; 32];

/// A running gateway with an alarm listener, and the shard its record lives under.
struct Stack {
    root: PathBuf,
    shard: ShardKey,
    gateway: String,
    alarm: String,
}

fn stack(name: &str) -> Stack {
    let root = temp_root(name);
    let vaults = start_vaults(&root);
    let router = remote_router(&vaults);
    let shard = shred_standard_record(&router);
    let assembler = start_assembler(Arc::clone(&router));
    let gateway = free_addr();
    let alarm = free_addr();
    start_gateway(&root, &assembler, &gateway, Some(&alarm));
    Stack {
        root,
        shard,
        gateway,
        alarm,
    }
}

/// A node-side alarm client. With `identity`, it presents the node's client certificate.
fn peer(addr: &str, identity: bool) -> AlarmPeer {
    let tls = if identity {
        client_config(
            &fixture("ca.pem"),
            Some((&fixture("client.pem"), &fixture("client.key"))),
        )
    } else {
        client_config(&fixture("ca.pem"), None)
    }
    .expect("client");
    AlarmPeer::new(addr, "localhost", tls, Duration::from_secs(5)).expect("peer")
}

fn token(key: &[u8; 32], version: u32, shard: &ShardKey) -> String {
    Signer::new(version, *key)
        .issue(shard, Scopes::from_scopes(&[Scope::Read]), now())
        .expect("issue")
        .to_string()
}

#[test]
fn a_pushed_key_replaces_the_old_one_and_is_audited() {
    let s = stack("rotate");
    let path = format!("/v1/records/{}", shard_hex(&s.shard));
    let old = token(&TOKEN_KEY, TOKEN_KEY_VERSION, &s.shard);
    assert_eq!(https_get(&s.gateway, &path, Some(&old)).0, 200);

    peer(&s.alarm, true)
        .push(2, &ROTATED_KEY)
        .expect("the node's push is accepted");

    // Tokens under the old key stop working, and tokens under the new key work.
    assert_eq!(https_get(&s.gateway, &path, Some(&old)).0, 401);
    let new = token(&ROTATED_KEY, 2, &s.shard);
    assert_eq!(https_get(&s.gateway, &path, Some(&new)).0, 200);

    // An equal or older version is refused, and the current key stays in force.
    assert!(peer(&s.alarm, true).push(2, &[0x73; 32]).is_err());
    assert!(peer(&s.alarm, true).push(1, &[0x74; 32]).is_err());
    assert_eq!(https_get(&s.gateway, &path, Some(&new)).0, 200);

    // The chain holds four entries: the first read, the rotation, and two reads under the new
    // key. The refused pushes left nothing, and the chain verifies under the gateway's key.
    let audit_path = s.root.join("gateway-state").join(AUDIT_LOG);
    let lines = fs::read_to_string(&audit_path).expect("audit log");
    assert_eq!(lines.lines().filter(|l| !l.is_empty()).count(), 4);
    AuditStore::open(&audit_path, AUDIT_KEY).expect("verifies under the gateway key");
    let _ = fs::remove_dir_all(&s.root);
}

#[test]
fn a_peer_without_the_node_certificate_cannot_rotate_the_key() {
    let s = stack("anonymous");
    let path = format!("/v1/records/{}", shard_hex(&s.shard));
    let old = token(&TOKEN_KEY, TOKEN_KEY_VERSION, &s.shard);
    assert_eq!(https_get(&s.gateway, &path, Some(&old)).0, 200);

    // The listener requires a client certificate, so the handshake is refused.
    let result = peer(&s.alarm, false).push(2, &ROTATED_KEY);
    assert_eq!(result.err(), Some(ShatterError::ServiceUnavailable));

    // The key did not change: the old token still reads.
    assert_eq!(https_get(&s.gateway, &path, Some(&old)).0, 200);
    let _ = fs::remove_dir_all(&s.root);
}

#[test]
fn an_alarm_listener_replaces_the_canary_acknowledgement() {
    let json = r#"{
        "listen": "127.0.0.1:1",
        "tls_cert": "c", "tls_key": "k",
        "state_dir": "s",
        "token_key_file": "t", "audit_key_file": "a",
        "acknowledge_canary_gap": false,
        "alarm": {"listen": "127.0.0.1:2", "client_ca": "ca"},
        "assembler": {"addr": "x:1", "server_name": "n", "ca": "c", "client_cert": "c", "client_key": "k"}
    }"#;
    GatewayConfig::from_json(json).expect("accepted with an alarm listener");
}
