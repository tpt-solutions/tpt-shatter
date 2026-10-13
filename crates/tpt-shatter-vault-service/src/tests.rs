// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Loopback mTLS tests. The certificates are the gateway's TEST-ONLY fixtures.

use std::net::TcpListener;

use tpt_shatter_common::FRAGMENT_ID_LEN;
use tpt_shatter_vault_client::MemoryVault;

use super::*;

const CA: &[u8] = include_bytes!("../../tpt-shatter-gateway/tests/fixtures/ca.pem");
const SERVER_CERT: &[u8] = include_bytes!("../../tpt-shatter-gateway/tests/fixtures/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../tpt-shatter-gateway/tests/fixtures/server.key");
const CLIENT_CERT: &[u8] = include_bytes!("../../tpt-shatter-gateway/tests/fixtures/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../tpt-shatter-gateway/tests/fixtures/client.key");

/// Starts a vault service for vault B on a free loopback port, and returns its address.
fn start() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let tls = server_tls(SERVER_CERT, SERVER_KEY, CA).expect("server tls");
    let store: Arc<dyn VaultBackend> = Arc::new(MemoryVault::new(VaultId::B));
    thread::spawn(move || {
        let _ = serve(listener, tls, store);
    });
    addr
}

fn remote(addr: &str, identity: Option<(&[u8], &[u8])>) -> RemoteVault {
    let tls = client_tls(CA, identity).expect("client tls");
    RemoteVault::new(VaultId::B, addr, "localhost", tls).expect("remote")
}

fn id(byte: u8) -> FragmentId {
    FragmentId::from_bytes([byte; FRAGMENT_ID_LEN])
}

#[test]
fn a_fragment_round_trips_over_mtls() {
    let addr = start();
    let vault = remote(&addr, Some((CLIENT_CERT, CLIENT_KEY)));
    let fragment = id(7);

    assert_eq!(vault.get(&fragment).expect("get"), None);
    vault.put(&fragment, b"sealed bytes").expect("put");
    assert_eq!(
        vault
            .get(&fragment)
            .expect("get")
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"sealed bytes"[..])
    );
    assert!(vault.delete(&fragment).expect("delete"));
    assert!(!vault.delete(&fragment).expect("delete again"));
    assert_eq!(vault.get(&fragment).expect("get after delete"), None);
}

#[test]
fn a_client_without_a_certificate_is_refused() {
    let addr = start();
    let vault = remote(&addr, None);
    assert_eq!(
        vault.put(&id(1), b"x"),
        Err(ShatterError::VaultUnavailable { vault: VaultId::B })
    );
}

#[test]
fn a_certificate_for_another_name_is_refused() {
    let addr = start();
    let tls = client_tls(CA, Some((CLIENT_CERT, CLIENT_KEY))).expect("client tls");
    let vault = RemoteVault::new(VaultId::B, &addr, "not-the-server.example", tls).expect("remote");
    assert!(vault.get(&id(1)).is_err());
}

#[test]
fn an_unknown_path_gets_no_fragment() {
    let addr = start();
    let tls = client_tls(CA, Some((CLIENT_CERT, CLIENT_KEY))).expect("client tls");
    let conn = ClientConnection::new(
        tls,
        ServerName::try_from("localhost".to_owned()).expect("name"),
    )
    .expect("conn");
    let tcp = TcpStream::connect(&addr).expect("connect");
    let mut stream = StreamOwned::new(conn, tcp);
    stream
        .write_all(b"GET /v1/other HTTP/1.1\r\nHost: vault\r\nConnection: close\r\n\r\n")
        .expect("write");
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 404"), "{out}");
}

#[test]
fn a_key_file_must_be_hex_and_private() {
    let dir = std::env::temp_dir().join(format!("tpt-vault-key-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("key");
    fs::write(&path, "ab".repeat(32)).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode");
        assert!(read_key_file(&path).is_err(), "group-readable key loaded");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("mode");
    }
    assert_eq!(read_key_file(&path).expect("key"), [0xAB; 32]);
    fs::write(&path, "zz").expect("write");
    assert!(read_key_file(&path).is_err(), "short key loaded");
    fs::remove_dir_all(&dir).expect("cleanup");
}
