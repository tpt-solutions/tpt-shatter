// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Shared setup for the gateway-service tests: vaults, assembler, and gateway on loopback TLS.
//! Uses synthetic data only. The certificates are the gateway crate's test fixtures.

#![allow(dead_code)]

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use tpt_shatter_assembler_service::{AssemblerSource, serve as serve_assembler};
use tpt_shatter_common::{Record, ShardKey, ShatterSchema, VaultId};
use tpt_shatter_gateway::remote::client_config;
use tpt_shatter_gateway::server_config;
use tpt_shatter_gateway_service::{GatewayConfig, run};
use tpt_shatter_vault_client::{
    BreakerConfig, FileVault, Guarded, Router, VaultBackend, system_clock,
};
use tpt_shatter_vault_service::{
    RemoteVault, client_tls_from_files, serve as serve_vault, server_tls,
};

pub const DERIVATION_KEY: [u8; 32] = [0xA1; 32];
pub const TOKEN_KEY: [u8; 32] = [0x71; 32];
pub const AUDIT_KEY: [u8; 32] = [0x81; 32];
const CARD: &str = "4000000000000002";

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tpt-shatter-gateway/tests/fixtures/"
    ))
    .join(name)
}

pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("fixture")
}

pub fn schema() -> ShatterSchema {
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

pub fn person() -> Record {
    let mut r = Record::new();
    r.insert("name", "Synthetic Person");
    r.insert("birth_year", "1994");
    r.insert("card_number", CARD);
    r
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("tpt-gw-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    root
}

/// An address nothing is listening on yet. There is a small race before it is used.
pub fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").to_string()
}

/// Starts the three vault services and returns their addresses.
pub fn start_vaults(root: &Path) -> [String; 3] {
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

pub fn remote_router(addresses: &[String; 3]) -> Arc<Router> {
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
pub fn start_assembler(router: Arc<Router>) -> String {
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

/// Shreds the standard record under shard `[0x5A; 32]` into the vaults.
pub fn shred_standard_record(router: &Arc<Router>) -> ShardKey {
    let shard = ShardKey::from_bytes([0x5A; 32]);
    let schema = schema();
    tpt_shatter_shredder::Shredder::new(&schema, router, DERIVATION_KEY)
        .shred(&shard, person())
        .expect("shred");
    shard
}

pub fn write_key(path: &Path, key: &[u8; 32]) {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(path, hex).expect("key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
}

/// Starts the gateway on `listen` with a config built from `root`. When `alarm_listen` is set,
/// the gateway also runs an alarm listener there, and no canary acknowledgement is needed.
/// It serves until the test process exits.
pub fn start_gateway(root: &Path, assembler: &str, listen: &str, alarm_listen: Option<&str>) {
    let token_path = root.join("token.key");
    let audit_path = root.join("gateway-audit.key");
    write_key(&token_path, &TOKEN_KEY);
    write_key(&audit_path, &AUDIT_KEY);
    let state = root.join("gateway-state");
    fs::create_dir_all(&state).expect("state");
    let mut json = serde_json::json!({
        "listen": listen,
        "tls_cert": fixture_path("server.pem"),
        "tls_key": fixture_path("server.key"),
        "state_dir": state,
        "token_key_file": token_path,
        "audit_key_file": audit_path,
        "acknowledge_canary_gap": alarm_listen.is_none(),
        "assembler": {
            "addr": assembler,
            "server_name": "localhost",
            "ca": fixture_path("ca.pem"),
            "client_cert": fixture_path("client.pem"),
            "client_key": fixture_path("client.key"),
        },
    });
    if let Some(alarm) = alarm_listen {
        json["alarm"] = serde_json::json!({
            "listen": alarm,
            "client_ca": fixture_path("ca.pem"),
        });
    }
    let config = GatewayConfig::from_json(&json.to_string()).expect("config");
    std::thread::spawn(move || {
        let _ = run(&config);
    });
}

/// One HTTPS request to the gateway. Returns the status and the body.
pub fn https_get(addr: &str, path: &str, bearer: Option<&str>) -> (u16, String) {
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

pub fn shard_hex(shard: &ShardKey) -> String {
    shard
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
