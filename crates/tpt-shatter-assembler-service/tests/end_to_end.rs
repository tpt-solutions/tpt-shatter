// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Gateway to assembler to vaults, all over loopback mTLS. Uses synthetic data only.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tpt_shatter_assembler_service::{AssemblerSource, serve};
use tpt_shatter_common::{Record, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_gateway::RecordSource;
use tpt_shatter_gateway::RemoteAssembler;
use tpt_shatter_gateway::remote::client_config;
use tpt_shatter_gateway::server_config;
use tpt_shatter_shredder::Shredder;
use tpt_shatter_vault_client::{
    BreakerConfig, FileVault, Guarded, Router, VaultBackend, system_clock,
};
use tpt_shatter_vault_service::{
    RemoteVault, client_tls_from_files, serve as serve_vault, server_tls,
};

const DERIVATION_KEY: [u8; 32] = [0xA1; 32];
const CARD: &str = "4000000000000002";

/// The gateway's test certificates. They are for loopback TLS only.
fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tpt-shatter-gateway/tests/fixtures/"
    ))
    .join(name);
    fs::read(path).expect("fixture")
}

fn schema() -> ShatterSchema {
    ShatterSchema::new(
        1,
        [
            ("name", VaultId::A),
            ("birth_year", VaultId::B),
            ("card_number", VaultId::C),
        ],
    )
    .expect("schema")
}

fn person() -> Record {
    let mut r = Record::new();
    r.insert("name", "Synthetic Person");
    r.insert("birth_year", "1994");
    r.insert("card_number", CARD);
    r
}

/// Starts the three vault services on loopback and returns their addresses.
fn start_vaults(root: &Path) -> [String; 3] {
    let mut addresses = Vec::new();
    for (vault, key_byte) in [(VaultId::A, 0x21u8), (VaultId::B, 0x22), (VaultId::C, 0x23)] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        addresses.push(listener.local_addr().expect("addr").to_string());
        let dir = root.join(format!("vault-{}", vault.label()));
        let store: Arc<dyn VaultBackend> =
            Arc::new(FileVault::open(vault, &dir, &[key_byte; 32]).expect("open"));
        let tls = server_tls(
            &fixture("server.pem"),
            &fixture("server.key"),
            &fixture("ca.pem"),
        )
        .expect("tls");
        std::thread::spawn(move || {
            let _ = serve_vault(listener, tls, store);
        });
    }
    [
        addresses[0].clone(),
        addresses[1].clone(),
        addresses[2].clone(),
    ]
}

/// A router of remote vault clients, as the assembler service builds its own.
fn remote_router(addresses: &[String; 3]) -> Arc<Router> {
    let tls = client_tls_from_files(
        &fixture_path("ca.pem"),
        &fixture_path("client.pem"),
        &fixture_path("client.key"),
    )
    .expect("client tls");
    let guards = [VaultId::A, VaultId::B, VaultId::C]
        .into_iter()
        .zip(addresses)
        .map(|(vault, addr)| {
            let backend: Box<dyn VaultBackend> = Box::new(
                RemoteVault::new(vault, addr, "localhost", Arc::clone(&tls)).expect("remote"),
            );
            Guarded::new(backend, BreakerConfig::default(), system_clock())
        })
        .collect();
    Arc::new(Router::new(guards).expect("router"))
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tpt-shatter-gateway/tests/fixtures/"
    ))
    .join(name)
}

/// Starts the assembler service on loopback and returns its address.
fn start_assembler(router: Arc<Router>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let tls = server_config(
        &fixture("server.pem"),
        &fixture("server.key"),
        Some(&fixture("ca.pem")),
    )
    .expect("server tls");
    let source = AssemblerSource::new(
        Arc::new(schema()),
        router,
        DERIVATION_KEY,
        Duration::from_secs(3),
    );
    std::thread::spawn(move || {
        let _ = serve(listener, tls, Arc::new(source));
    });
    addr
}

fn client_with_identity(addr: &str) -> RemoteAssembler {
    let tls = client_config(
        &fixture("ca.pem"),
        Some((&fixture("client.pem"), &fixture("client.key"))),
    )
    .expect("client config");
    RemoteAssembler::new(addr, "localhost", tls, Duration::from_secs(5)).expect("client")
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("tpt-asm-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    root
}

#[test]
fn a_gateway_reads_a_record_back_through_the_assembler_service() {
    let root = temp_root("roundtrip");
    let vaults = start_vaults(&root);
    let router = remote_router(&vaults);

    let shard = ShardKey::from_bytes([0x5A; 32]);
    let schema = schema();
    Shredder::new(&schema, &router, DERIVATION_KEY)
        .shred(&shard, person())
        .expect("shred");

    let assembler = start_assembler(Arc::clone(&router));
    let client = client_with_identity(&assembler);
    let record = client.fetch(&shard).expect("fetch");

    assert_eq!(record.get("name"), Some("Synthetic Person"));
    assert_eq!(record.get("birth_year"), Some("1994"));
    assert_eq!(record.get("card_number"), Some(CARD));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_shard_with_no_fragments_returns_no_record() {
    let root = temp_root("missing");
    let vaults = start_vaults(&root);
    let router = remote_router(&vaults);
    let assembler = start_assembler(router);
    let client = client_with_identity(&assembler);

    let result = client.fetch(&ShardKey::from_bytes([0x6B; 32]));
    assert!(
        result.is_err(),
        "a shard with no fragments must not return a record"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_client_without_a_certificate_is_refused() {
    let root = temp_root("anonymous");
    let vaults = start_vaults(&root);
    let assembler = start_assembler(remote_router(&vaults));

    let tls = client_config(&fixture("ca.pem"), None).expect("client config");
    let client =
        RemoteAssembler::new(&assembler, "localhost", tls, Duration::from_secs(5)).expect("client");
    let result = client.fetch(&ShardKey::from_bytes([0x5A; 32]));
    assert_eq!(result.err(), Some(ShatterError::ServiceUnavailable));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_unreachable_assembler_is_service_unavailable() {
    // Bind and drop, so the port is closed.
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").to_string()
    };
    let client = client_with_identity(&addr);
    let result = client.fetch(&ShardKey::from_bytes([0x5A; 32]));
    assert_eq!(result.err(), Some(ShatterError::ServiceUnavailable));
}
