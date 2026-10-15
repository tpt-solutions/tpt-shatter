// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Client to gateway to assembler to vaults, all over loopback TLS. Uses synthetic data only.

mod common;

use std::fs;
use std::sync::Arc;

use common::*;
use tpt_shatter_common::{AuditStore, Scope, Scopes, ShardKey};
use tpt_shatter_gateway_service::{AUDIT_LOG, GatewayConfig, TOKEN_KEY_VERSION};
use tpt_shatter_token::Signer;

#[test]
fn a_token_reads_a_record_through_the_gateway_and_is_audited() {
    let root = temp_root("read");
    let vaults = start_vaults(&root);
    let router = remote_router(&vaults);
    let shard = shred_standard_record(&router);
    let assembler = start_assembler(Arc::clone(&router));
    let gateway = free_addr();
    start_gateway(&root, &assembler, &gateway, None);

    let token = Signer::new(TOKEN_KEY_VERSION, TOKEN_KEY)
        .issue(&shard, Scopes::from_scopes(&[Scope::Read]), now())
        .expect("issue");
    let path = format!("/v1/records/{}", shard_hex(&shard));

    // Refused before any read: no token, and a token for another shard.
    let (status, _) = https_get(&gateway, &path, None);
    assert_eq!(status, 401);
    let other = ShardKey::from_bytes([0x6B; 32]);
    let wrong_shard = Signer::new(TOKEN_KEY_VERSION, TOKEN_KEY)
        .issue(&other, Scopes::from_scopes(&[Scope::Read]), now())
        .expect("issue");
    let (status, _) = https_get(&gateway, &path, Some(&wrong_shard));
    assert_eq!(status, 401);

    // The authorized read succeeds and returns the record.
    let (status, body) = https_get(&gateway, &path, Some(&token));
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("Synthetic Person"), "body: {body}");
    assert!(body.contains("1994"), "body: {body}");

    // Exactly one authorized read is on the gateway's chain, and the chain verifies under
    // the gateway's own key. The refused requests left nothing.
    let audit_path = root.join("gateway-state").join(AUDIT_LOG);
    let lines = fs::read_to_string(&audit_path).expect("audit log");
    assert_eq!(lines.lines().filter(|l| !l.is_empty()).count(), 1);
    AuditStore::open(&audit_path, AUDIT_KEY).expect("verifies under the gateway key");

    // The node's audit key cannot open this chain, so the two chains are separate.
    let node_key = [0x99u8; 32];
    assert!(AuditStore::open(&audit_path, node_key).is_err());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_config_without_an_alarm_listener_or_the_acknowledgement_is_refused() {
    let json = r#"{
        "listen": "127.0.0.1:1",
        "tls_cert": "c", "tls_key": "k",
        "state_dir": "s",
        "token_key_file": "t", "audit_key_file": "a",
        "acknowledge_canary_gap": false,
        "assembler": {"addr": "x:1", "server_name": "n", "ca": "c", "client_cert": "c", "client_key": "k"}
    }"#;
    let err = GatewayConfig::from_json(json).expect_err("refused");
    assert!(err.contains("acknowledge_canary_gap"), "{err}");
}

#[test]
fn an_unknown_config_field_is_refused() {
    let json = r#"{"listen":"x","bogus":1}"#;
    assert!(GatewayConfig::from_json(json).is_err());
}
