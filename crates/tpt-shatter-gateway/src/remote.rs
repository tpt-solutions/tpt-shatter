// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The link from the gateway to the assembler service, over mTLS.
//!
//! The gateway is the only client. It sends a shard, and the assembler answers with the
//! record as `{"fields": {name: value}}`, or with an error code. A failure that names a
//! vault carries the vault label and nothing else. One request goes on each connection,
//! with `Connection: close`, and the response is read to its end.
//!
//! [`RemoteAssembler`] implements [`RecordSource`], so the gateway uses it in place of an
//! in-process assembler. The wire functions here are shared with the assembler service,
//! so both ends agree on the format.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::version::TLS13;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Map, Value, json};
use tpt_shatter_common::{Record, ShardKey, ShatterError, VaultId};

use crate::RecordSource;

/// The most response bytes the client reads. A record is bounded by its schema, far below this.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Builds a TLS 1.3 client configuration. It trusts `ca_pem` for the assembler's certificate,
/// and presents `identity` (certificate chain, then key) when one is given.
///
/// Errors are fixed values. The PEM input is never echoed.
pub fn client_config(
    ca_pem: &[u8],
    identity: Option<(&[u8], &[u8])>,
) -> Result<Arc<ClientConfig>, ShatterError> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(ca_pem) {
        roots
            .add(ca.map_err(|_| ShatterError::InvalidParameter)?)
            .map_err(|_| ShatterError::InvalidParameter)?;
    }
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| ShatterError::InvalidParameter)?
        .with_root_certificates(roots);
    let config = match identity {
        Some((cert_pem, key_pem)) => {
            let chain = CertificateDer::pem_slice_iter(cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ShatterError::InvalidParameter)?;
            let key = PrivateKeyDer::from_pem_slice(key_pem)
                .map_err(|_| ShatterError::InvalidParameter)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|_| ShatterError::InvalidParameter)?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// A [`RecordSource`] that asks the assembler service for each record over mTLS.
pub struct RemoteAssembler {
    addr: String,
    server_name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    timeout: Duration,
}

impl RemoteAssembler {
    /// Creates a client for the assembler at `addr` (`host:port`). `server_name` must match
    /// the name on the assembler's certificate. `timeout` bounds connecting and each read or
    /// write.
    pub fn new(
        addr: &str,
        server_name: &str,
        tls: Arc<ClientConfig>,
        timeout: Duration,
    ) -> Result<Self, ShatterError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| ShatterError::InvalidParameter)?;
        Ok(Self {
            addr: addr.to_owned(),
            server_name,
            tls,
            timeout,
        })
    }

    fn exchange(&self, request: &[u8]) -> Result<(u16, Vec<u8>), ShatterError> {
        let addr = self
            .addr
            .to_socket_addrs()
            .map_err(unavailable)?
            .next()
            .ok_or(ShatterError::ServiceUnavailable)?;
        let tcp = TcpStream::connect_timeout(&addr, self.timeout).map_err(unavailable)?;
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(unavailable)?;
        tcp.set_write_timeout(Some(self.timeout))
            .map_err(unavailable)?;
        let conn = ClientConnection::new(Arc::clone(&self.tls), self.server_name.clone())
            .map_err(unavailable)?;
        let mut stream = StreamOwned::new(conn, tcp);
        stream.write_all(request).map_err(unavailable)?;

        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if response.len() + n > MAX_RESPONSE_BYTES {
                        return Err(ShatterError::Internal);
                    }
                    response.extend_from_slice(&chunk[..n]);
                }
                // Some peers close TLS without a close_notify. The length check in
                // `parse_response` decides whether the body is complete.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return Err(ShatterError::ServiceUnavailable),
            }
        }
        // Nothing came back: the peer closed the connection, for example after refusing the
        // client certificate. That is an unavailable service, not a malformed reply.
        if response.is_empty() {
            return Err(ShatterError::ServiceUnavailable);
        }
        parse_response(&response)
    }
}

impl RecordSource for RemoteAssembler {
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        let request = format!(
            "GET {}{} HTTP/1.1\r\nHost: assembler\r\nConnection: close\r\n\r\n",
            RECORD_PATH,
            shard_hex(shard)
        );
        let (status, body) = self.exchange(request.as_bytes())?;
        if status == 200 {
            decode_record(&body)
        } else {
            Err(decode_error(&body))
        }
    }
}

/// The path prefix for a record request. The shard's hex follows it.
pub const RECORD_PATH: &str = "/v1/records/";

/// Any failure to reach or talk to the assembler is the same error to the caller.
fn unavailable<E>(_: E) -> ShatterError {
    ShatterError::ServiceUnavailable
}

/// Renders a shard key as 64 lowercase hex characters, for the request path.
#[must_use]
pub fn shard_hex(shard: &ShardKey) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in shard.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Splits an HTTP/1.1 response into its status and body. The body must match
/// `Content-Length` when that header is present.
pub fn parse_response(bytes: &[u8]) -> Result<(u16, Vec<u8>), ShatterError> {
    let head_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(ShatterError::Internal)?;
    let head = std::str::from_utf8(&bytes[..head_end]).map_err(|_| ShatterError::Internal)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(ShatterError::Internal)?;
    let mut parts = status_line.split(' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(ShatterError::Internal);
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(ShatterError::Internal)?;

    let body = &bytes[head_end + 4..];
    let declared = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    match declared {
        Some(len) if len != body.len() => Err(ShatterError::Internal),
        _ => Ok((status, body.to_vec())),
    }
}

/// Encodes a record as `{"fields": {name: value}}`.
#[must_use]
pub fn encode_record(record: &Record) -> Vec<u8> {
    let mut fields = Map::new();
    for name in record.field_names() {
        if let Some(value) = record.get(name) {
            fields.insert(name.to_owned(), Value::String(value.to_owned()));
        }
    }
    serde_json::to_vec(&json!({ "fields": fields })).unwrap_or_default()
}

/// Decodes `{"fields": {name: value}}`. Values must be strings.
pub fn decode_record(body: &[u8]) -> Result<Record, ShatterError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ShatterError::Internal)?;
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .ok_or(ShatterError::Internal)?;
    let mut record = Record::new();
    for (name, value) in fields {
        let value = value.as_str().ok_or(ShatterError::Internal)?;
        record.insert(name.clone(), value);
    }
    Ok(record)
}

/// Maps an error to the status and body the assembler service answers with. The body names
/// the error and, for a vault failure, the vault. It never carries record data.
#[must_use]
pub fn encode_error(error: ShatterError) -> (u16, Vec<u8>) {
    let (status, body) = match error {
        ShatterError::InvalidShardKey => (400, json!({ "error": "invalid_shard_key" })),
        ShatterError::Reconstruction => (404, json!({ "error": "reconstruction" })),
        ShatterError::VaultUnavailable { vault } => (
            503,
            json!({ "error": "vault_unavailable", "vault": vault.label().to_string() }),
        ),
        ShatterError::ServiceUnavailable => (503, json!({ "error": "unavailable" })),
        _ => (500, json!({ "error": "internal" })),
    };
    (status, serde_json::to_vec(&body).unwrap_or_default())
}

/// Maps an error body from the assembler service back to a [`ShatterError`]. Anything
/// unrecognized is [`ShatterError::Internal`].
#[must_use]
pub fn decode_error(body: &[u8]) -> ShatterError {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return ShatterError::Internal;
    };
    match value.get("error").and_then(Value::as_str) {
        Some("invalid_shard_key") => ShatterError::InvalidShardKey,
        Some("reconstruction") => ShatterError::Reconstruction,
        Some("vault_unavailable") => value
            .get("vault")
            .and_then(Value::as_str)
            .and_then(|label| label.chars().next())
            .and_then(|c| VaultId::from_label(c).ok())
            .map_or(ShatterError::ServiceUnavailable, |vault| {
                ShatterError::VaultUnavailable { vault }
            }),
        Some("unavailable") => ShatterError::ServiceUnavailable,
        _ => ShatterError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        let mut r = Record::new();
        r.insert("name", "Synthetic Person");
        r.insert("birth_year", "1994");
        r
    }

    #[test]
    fn a_record_round_trips_through_the_wire_format() {
        let back = decode_record(&encode_record(&record())).expect("decode");
        assert_eq!(back.get("name"), Some("Synthetic Person"));
        assert_eq!(back.get("birth_year"), Some("1994"));
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn a_non_string_field_is_refused() {
        assert!(decode_record(br#"{"fields":{"name":5}}"#).is_err());
        assert!(decode_record(br#"{"nope":{}}"#).is_err());
    }

    #[test]
    fn errors_round_trip_and_name_the_vault() {
        for error in [
            ShatterError::InvalidShardKey,
            ShatterError::Reconstruction,
            ShatterError::VaultUnavailable { vault: VaultId::B },
            ShatterError::ServiceUnavailable,
        ] {
            let (_, body) = encode_error(error);
            assert_eq!(decode_error(&body), error);
        }
        // An error with no mapping is Internal, and the body carries no detail to leak.
        let (status, body) = encode_error(ShatterError::Unauthorized);
        assert_eq!(status, 500);
        assert_eq!(decode_error(&body), ShatterError::Internal);
    }

    #[test]
    fn a_response_is_split_at_its_declared_length() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(parse_response(ok).expect("ok"), (200, b"hi".to_vec()));
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhi";
        assert!(parse_response(short).is_err());
        let not_http = b"SMTP/1.0 200\r\n\r\n";
        assert!(parse_response(not_http).is_err());
    }

    #[test]
    fn the_shard_renders_as_64_hex_characters() {
        let shard = ShardKey::from_bytes([0xAB; 32]);
        let hex = shard_hex(&shard);
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("abab"));
        assert_eq!(shard_hex(&ShardKey::from_hex(&hex).expect("parse")), hex);
    }
}
