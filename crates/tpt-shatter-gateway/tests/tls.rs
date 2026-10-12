// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! End-to-end TLS tests: a real handshake against the gateway's TLS listener.

use std::sync::{Arc, RwLock};

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::version::TLS13;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tpt_shatter_common::{Record, ShardKey, ShatterError};
use tpt_shatter_gateway::{
    Gateway, HttpConfig, RateLimiter, Shared, acceptor, serve_tls, server_config,
};
use tpt_shatter_token::Signer;

const SERVER_CERT: &[u8] = include_bytes!("fixtures/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/server.key");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CLIENT_CERT: &[u8] = include_bytes!("fixtures/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("fixtures/client.key");

type Source = fn(&ShardKey) -> Result<Record, ShatterError>;

fn no_records(_: &ShardKey) -> Result<Record, ShatterError> {
    Err(ShatterError::Reconstruction)
}

async fn start(client_ca: Option<&[u8]>) -> std::net::SocketAddr {
    let config = server_config(SERVER_CERT, SERVER_KEY, client_ca).expect("server config");
    let signer = Arc::new(RwLock::new(Signer::new(1, [0xA5; 32])));
    let source: Source = no_records;
    let gateway = Gateway::new(
        signer,
        source,
        RateLimiter::new(100, 1, 100).expect("limiter"),
    );
    let shared = Arc::new(Shared {
        gateway: Arc::new(gateway),
        breakers: Arc::new(|| vec![false]),
        access_log: Arc::new(|_: &str| {}),
        config: HttpConfig::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(serve_tls(listener, shared, acceptor(config)));
    addr
}

fn roots(ca_pem: &[u8]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem) {
        store.add(cert.expect("ca pem")).expect("add root");
    }
    store
}

fn client_config(trust: RootCertStore, identity: Option<(&[u8], &[u8])>) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("versions")
        .with_root_certificates(trust);
    let config = match identity {
        Some((cert, key)) => {
            let chain = CertificateDer::pem_slice_iter(cert)
                .collect::<Result<Vec<_>, _>>()
                .expect("client cert");
            let key = PrivateKeyDer::from_pem_slice(key).expect("client key");
            builder
                .with_client_auth_cert(chain, key)
                .expect("client auth")
        }
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

/// Performs the handshake and a health request. Returns the response text, or the
/// error if any step (connect, handshake, write, read) failed.
async fn get_health(
    addr: std::net::SocketAddr,
    config: Arc<ClientConfig>,
) -> std::io::Result<String> {
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("localhost").expect("name");
    let mut tls = TlsConnector::from(config).connect(name, tcp).await?;
    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn trusted_client_gets_a_response_over_tls13() {
    let addr = start(None).await;
    let out = get_health(addr, client_config(roots(CA), None))
        .await
        .expect("tls request");
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains(r#"{"status":"live"}"#));
}

#[tokio::test]
async fn client_that_does_not_trust_the_ca_is_refused() {
    let addr = start(None).await;
    let result = get_health(addr, client_config(RootCertStore::empty(), None)).await;
    let answered = result
        .map(|out| out.contains("HTTP/1.1 200"))
        .unwrap_or(false);
    assert!(!answered, "untrusted client must not get a response");
}

#[tokio::test]
async fn mtls_refuses_a_client_without_a_certificate() {
    let addr = start(Some(CA)).await;
    let result = get_health(addr, client_config(roots(CA), None)).await;
    let answered = result
        .map(|out| out.contains("HTTP/1.1 200"))
        .unwrap_or(false);
    assert!(!answered, "mTLS must reject a client with no certificate");
}

#[tokio::test]
async fn mtls_accepts_a_client_with_a_ca_issued_certificate() {
    let addr = start(Some(CA)).await;
    let out = get_health(
        addr,
        client_config(roots(CA), Some((CLIENT_CERT, CLIENT_KEY))),
    )
    .await
    .expect("mtls request");
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}
