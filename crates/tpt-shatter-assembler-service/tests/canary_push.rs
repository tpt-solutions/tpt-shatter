// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The node's canary list push, over loopback mTLS: a newer list is written, an older one is
//! refused, and a client without the node certificate is turned away. Synthetic data only.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use tpt_shatter_assembler_service::serve_canary_list;
use tpt_shatter_canary::{CanaryIds, CanaryRotation};
use tpt_shatter_common::ShatterError;
use tpt_shatter_gateway::remote::{CanaryPeer, client_config};
use tpt_shatter_gateway::server_config;

const MASTER: [u8; 32] = [0xC1; 32];
const DERIVATION: [u8; 32] = [0xC2; 32];
const WEEK: u64 = 7 * 24 * 3600;

/// The gateway crate's TLS test fixtures. They are for loopback TLS only.
fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tpt-shatter-gateway/tests/fixtures")
        .join(name);
    fs::read(path).expect("fixture")
}

fn temp_list(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tpt-canary-push-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("dir");
    dir.join("canary-ids.txt")
}

fn ids_for(epoch: u64) -> CanaryIds {
    let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
    let plan = rotation.plan_for_epoch(epoch).expect("plan");
    CanaryIds::from_plan(&plan, epoch).expect("ids")
}

/// Starts a list listener on loopback that writes to `list`. Returns its address.
fn listener_for(list: PathBuf) -> String {
    let tls = server_config(
        &fixture("server.pem"),
        &fixture("server.key"),
        Some(&fixture("ca.pem")),
    )
    .expect("server config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    thread::spawn(move || {
        let _ = serve_canary_list(listener, tls, list);
    });
    addr
}

#[test]
fn a_newer_list_is_written_and_an_older_one_is_refused() {
    let list = temp_list("order");
    ids_for(50).write_file(&list).expect("seed list");
    let addr = listener_for(list.clone());

    let tls = client_config(
        &fixture("ca.pem"),
        Some((&fixture("client.pem"), &fixture("client.key"))),
    )
    .expect("client config");
    let peer = CanaryPeer::new(&addr, "localhost", tls, Duration::from_secs(5)).expect("peer");

    peer.push(&ids_for(51).to_text())
        .expect("newer list accepted");
    assert_eq!(CanaryIds::read_file(&list).expect("read").epoch(), 51);

    assert_eq!(
        peer.push(&ids_for(49).to_text()),
        Err(ShatterError::InvalidParameter)
    );
    assert_eq!(CanaryIds::read_file(&list).expect("read").epoch(), 51);
}

#[test]
fn a_client_without_the_node_certificate_cannot_push() {
    let list = temp_list("auth");
    ids_for(50).write_file(&list).expect("seed list");
    let addr = listener_for(list.clone());

    let tls = client_config(&fixture("ca.pem"), None).expect("client config");
    let peer = CanaryPeer::new(&addr, "localhost", tls, Duration::from_secs(5)).expect("peer");

    assert!(peer.push(&ids_for(51).to_text()).is_err());
    assert_eq!(CanaryIds::read_file(&list).expect("read").epoch(), 50);
}
