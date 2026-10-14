// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Client to gateway to assembler to vaults, all over loopback TLS. Uses synthetic data only.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use tpt_shatter_assembler_service::{AssemblerSource, serve as serve_assembler};
use tpt_shatter_common::{AuditStore, Record, Scope, Scopes, ShardKey, ShatterSchema, VaultId};
use tpt_shatter_gateway::remote::client_config;
use tpt_shatter_gateway::server_config;
use tpt_shatter_gateway_service::{AUDIT_LOG, GatewayConfig, TOKEN_KEY_VERSION, run};
use tpt_shatter_shredder::Shredder;
use tpt_shatter_token::Signer;
use tpt_shatter_vault_client::{
    BreakerConfig, FileVault, Guarded, Router, VaultBackend, system_clock,
};
use tpt_shatter_vault_service::{
    RemoteVault, client_tls_from_files, serve as serve_vault, server_tls,
};

const DERIVATION_KEY: [u8; 32] = [0xA1; 32];
const TOKEN_KEY: [u8; 32] = [0x71; 32];
const AUDIT_KEY: [u8; 32] = [0x81; 32];
const CARD: &str = "4000000000000002";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tpt-shatter-gateway/tests/fixtures/"
    ))
    .join(name)
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("fixture")
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("tpt-gw-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    root
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").to_string()
}

/// Starts the three vault services and returns their addresses.
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

/// Starts the assembler service and returns its address.
fn start_assembler(router: Arc<Router>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let tls = server_config(
        &fixture("server.pem"),
        &fixture("server.key"),
        Some(&fixture("ca.pem")),
    )
    .expect("tls");
    let source = AssemblerSource::new(
        Arc::new(schema()),
        router,
        DERIVATION_KEY,
        Duration::from_secs(3),
    );
    std::thread::spawn(move || {
        let _ = serve_assembler(listener, tls, Arc::new(source));
    });
    addr
}

fn write_key(path: &Path, key: &[u8; 32]) {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(path, hex).expect("key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
}

/// Starts the gateway on `listen` with a config built from `root`. It serves until the test
/// process exits.
fn start_gateway(root: &Path, assembler: &str, listen: &str) {
    let token_path = root.join("token.key");
    let audit_path = root.join("gateway-audit.key");
    write_key(&token_path, &TOKEN_KEY);
    write_key(&audit_path, &AUDIT_KEY);
    let state = root.join("gateway-state");
    fs::create_dir_all(&state).expect("state");
    let json = serde_json::json!({
        "listen": listen,
        "tls_cert": fixture_path("server.pem"),
        "tls_key": fixture_path("server.key"),
        "state_dir": state,
        "token_key_file": token_path,
        "audit_key_file": audit_path,
        "acknowledge_canary_gap": true,
        "assembler": {
            "addr": assembler,
            "server_name": "localhost",
            "ca": fixture_path("ca.pem"),
            "client_cert": fixture_path("client.pem"),
            "client_key": fixture_path("client.key"),
        },
    })
    .to_string();
    let config = GatewayConfig::from_json(&json).expect("config");
    std::thread::spawn(move || {
        let _ = run(&config);
    });
}

/// One HTTPS request to the gateway. Returns the status and the body.
fn https_get(addr: &str, path: &str, bearer: Option<&str>) -> (u16, String) {
    let tls = client_config(&fixture("ca.pem"), None).expect("client");
    let mut tcp = None;
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr) {
            tcp = Some(stream);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let tcp = tcp.expect("gateway is listening");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let conn = ClientConnection::new(
        tls,
        ServerName::try_from("localhost".to_owned()).expect("name"),
    )
    .expect("conn");
    let mut stream = StreamOwned::new(conn, tcp);
    let auth = bearer.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write");
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("read: {e}"),
        }
    }
    let text = String::from_utf8(bytes).expect("utf8");
    let status: u16 = text
        .split(' ')
        .nth(1)
        .expect("status")
        .parse()
        .expect("code");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, body)
}

fn shard_hex(shard: &ShardKey) -> String {
    shard
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_token_reads_a_record_through_the_gateway_and_is_audited() {
    let root = temp_root("read");
    let vaults = start_vaults(&root);
    let router = remote_router(&vaults);
    let shard = ShardKey::from_bytes([0x5A; 32]);
    let schema = schema();
    Shredder::new(&schema, &router, DERIVATION_KEY)
        .shred(&shard, person())
        .expect("shred");
    let assembler = start_assembler(Arc::clone(&router));
    let gateway = free_addr();
    start_gateway(&root, &assembler, &gateway);

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
fn a_config_without_the_canary_acknowledgement_is_refused() {
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
