// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! TLS for the gateway: rustls with the graviola crypto provider.
//!
//! The provider is pure Rust. It is dual-licensed `Apache-2.0 OR ISC OR MIT-0`, and
//! the ISC option satisfies `deny.toml`. Neither `ring` nor `aws-lc-rs` is in the
//! tree, since both carry Apache-only components (see `DECISIONS.md`).
//!
//! Only TLS 1.3 is offered. Client certificates are optional. When a client CA is
//! given, the server requires a client certificate chaining to it (mTLS).

use std::sync::Arc;

use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tpt_shatter_common::ShatterError;

/// Builds a TLS 1.3 server configuration from PEM data.
///
/// `cert_pem` is the server certificate chain, `key_pem` its private key. When
/// `client_ca_pem` is `Some`, clients must present a certificate issued by that CA.
///
/// Errors are fixed values. The PEM input is never echoed.
pub fn server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, ShatterError> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let chain = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ShatterError::InvalidParameter)?;
    if chain.is_empty() {
        return Err(ShatterError::InvalidParameter);
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| ShatterError::InvalidParameter)?;

    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| ShatterError::InvalidParameter)?;

    let config = match client_ca_pem {
        Some(ca_pem) => {
            let mut roots = RootCertStore::empty();
            for ca in CertificateDer::pem_slice_iter(ca_pem) {
                let ca = ca.map_err(|_| ShatterError::InvalidParameter)?;
                roots.add(ca).map_err(|_| ShatterError::InvalidParameter)?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|_| ShatterError::InvalidParameter)?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(chain, key)
        }
        None => builder.with_no_client_auth().with_single_cert(chain, key),
    }
    .map_err(|_| ShatterError::InvalidParameter)?;

    Ok(Arc::new(config))
}

/// Wraps a server configuration in an acceptor for [`crate::serve_tls`].
#[must_use]
pub fn acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &[u8] = include_bytes!("../tests/fixtures/server.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/server.key");
    const CA: &[u8] = include_bytes!("../tests/fixtures/ca.pem");

    #[test]
    fn builds_tls13_config_from_fixtures() {
        assert!(server_config(CERT, KEY, None).is_ok());
    }

    #[test]
    fn builds_mtls_config_from_fixtures() {
        assert!(server_config(CERT, KEY, Some(CA)).is_ok());
    }

    #[test]
    fn rejects_missing_or_malformed_material_without_echoing_it() {
        assert_eq!(
            server_config(b"", KEY, None).err(),
            Some(ShatterError::InvalidParameter)
        );
        assert_eq!(
            server_config(CERT, b"not a key", None).err(),
            Some(ShatterError::InvalidParameter)
        );
        assert_eq!(
            server_config(CERT, KEY, Some(b"garbage")).err(),
            Some(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_a_key_that_does_not_match_the_certificate() {
        let other_key = include_bytes!("../tests/fixtures/client.key");
        assert_eq!(
            server_config(CERT, other_key, None).err(),
            Some(ShatterError::InvalidParameter)
        );
    }
}
