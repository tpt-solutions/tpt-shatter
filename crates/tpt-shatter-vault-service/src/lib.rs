// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! One vault served over mTLS, and the client the node uses to reach it.
//!
//! A vault service holds the vault's sealing key and nothing else, so each vault can run on
//! its own host. The node holds no vault key in this mode. The wire protocol is documented in
//! `README.md`. Every request is one connection with `Connection: close`, and every response
//! carries `Content-Length`, so neither side depends on the peer closing the stream.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rustls::version::TLS13;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tpt_shatter_common::{FragmentId, ShatterError, VaultId};
use tpt_shatter_vault_client::VaultBackend;
use zeroize::Zeroizing;

/// Per-socket read and write timeout, for both sides.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest request or response head the protocol accepts, in bytes.
const MAX_HEAD: usize = 8 * 1024;
/// Largest sealed fragment body, in bytes. Fragments are small; this bounds memory per request.
const MAX_BODY: usize = 64 * 1024;
/// Most connections served at once. Excess connections are dropped, not queued.
pub const MAX_CONNECTIONS: usize = 64;
const FRAGMENT_PATH: &str = "/v1/fragments/";

/// Builds the server's TLS configuration. Client certificates are required and must chain to
/// `client_ca_pem`.
pub fn server_tls(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, ShatterError> {
    tpt_shatter_gateway::server_config(cert_pem, key_pem, Some(client_ca_pem))
}

/// Builds a client TLS configuration that trusts `ca_pem` for server certificates. `identity`
/// is the client certificate chain and key, or `None` to present no client certificate.
pub fn client_tls(
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

/// [`client_tls`] with the CA and identity read from PEM files. Errors name no file contents.
pub fn client_tls_from_files(
    ca: &Path,
    cert: &Path,
    key: &Path,
) -> Result<Arc<ClientConfig>, ShatterError> {
    let read = |path: &Path| fs::read(path).map_err(|_| ShatterError::InvalidParameter);
    let ca = read(ca)?;
    let cert = read(cert)?;
    let key = read(key)?;
    client_tls(&ca, Some((&cert, &key)))
}

/// Reads a 32-byte key from a file of 64 hex characters. On Unix, a file readable or writable
/// by group or others is refused. Errors never include the file's contents.
pub fn read_key_file(path: &Path) -> Result<[u8; 32], ShatterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|_| ShatterError::InvalidParameter)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(ShatterError::InvalidParameter);
        }
    }
    let text =
        Zeroizing::new(fs::read_to_string(path).map_err(|_| ShatterError::InvalidParameter)?);
    let hex = text.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(ShatterError::InvalidParameter);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| ShatterError::InvalidParameter)?;
    }
    Ok(out)
}

/// Serves `store` on `listener` until the listener fails. Each connection is handled on its
/// own thread, up to [`MAX_CONNECTIONS`] at a time.
pub fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    store: Arc<dyn VaultBackend>,
) -> Result<(), ShatterError> {
    let live = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        let Ok(tcp) = connection else { continue };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (tls, store, live) = (Arc::clone(&tls), Arc::clone(&store), Arc::clone(&live));
        thread::spawn(move || {
            let _ = handle(tcp, tls, store.as_ref());
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(
    tcp: TcpStream,
    tls: Arc<ServerConfig>,
    store: &dyn VaultBackend,
) -> Result<(), ShatterError> {
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let conn = ServerConnection::new(tls).map_err(|_| ShatterError::Internal)?;
    let mut stream = StreamOwned::new(conn, tcp);
    let response = match read_request(&mut stream) {
        Ok((method, path, body)) => route(store, &method, &path, &body),
        Err(_) => Response::status(400),
    };
    write_response(&mut stream, &response)
}

/// What the server answers with.
struct Response {
    status: u16,
    body: Zeroizing<Vec<u8>>,
    json: bool,
}

impl Response {
    fn status(status: u16) -> Self {
        Self {
            status,
            body: Zeroizing::new(Vec::new()),
            json: false,
        }
    }
}

fn route(store: &dyn VaultBackend, method: &str, path: &str, body: &[u8]) -> Response {
    let Some(hex) = path.strip_prefix(FRAGMENT_PATH) else {
        return Response::status(404);
    };
    let Ok(id) = FragmentId::from_hex(hex) else {
        return Response::status(400);
    };
    match method {
        "PUT" => match store.put(&id, body) {
            Ok(()) => Response::status(204),
            Err(_) => Response::status(503),
        },
        "GET" => match store.get(&id) {
            Ok(Some(bytes)) => Response {
                status: 200,
                body: bytes,
                json: false,
            },
            Ok(None) => Response::status(404),
            Err(_) => Response::status(503),
        },
        "DELETE" => match store.delete(&id) {
            Ok(removed) => Response {
                status: 200,
                body: Zeroizing::new(format!("{{\"removed\":{removed}}}").into_bytes()),
                json: true,
            },
            Err(_) => Response::status(503),
        },
        _ => Response::status(405),
    }
}

fn read_request<S: Read>(stream: &mut S) -> Result<(String, String, Vec<u8>), ShatterError> {
    let (head, mut body) = read_head_and_rest(stream, MAX_HEAD)?;
    let head = std::str::from_utf8(&head).map_err(|_| ShatterError::InvalidParameter)?;
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split(' ');
    let method = request
        .next()
        .ok_or(ShatterError::InvalidParameter)?
        .to_owned();
    let path = request
        .next()
        .ok_or(ShatterError::InvalidParameter)?
        .to_owned();
    let length = content_length(lines)?.unwrap_or(0);
    if length > MAX_BODY {
        return Err(ShatterError::InvalidParameter);
    }
    read_exact_into(stream, &mut body, length)?;
    body.truncate(length);
    Ok((method, path, body))
}

fn write_response<S: Write>(stream: &mut S, response: &Response) -> Result<(), ShatterError> {
    let content_type = if response.json {
        "application/json"
    } else {
        "application/octet-stream"
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&response.body))
        .and_then(|()| stream.flush())
        .map_err(|_| ShatterError::Internal)
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Reads until the blank line that ends a head. Returns the head and any bytes after it.
fn read_head_and_rest<S: Read>(
    stream: &mut S,
    max: usize,
) -> Result<(Vec<u8>, Vec<u8>), ShatterError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buf) {
            let rest = buf.split_off(end + 4);
            buf.truncate(end);
            return Ok((buf, rest));
        }
        if buf.len() > max {
            return Err(ShatterError::InvalidParameter);
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|_| ShatterError::InvalidParameter)?;
        if n == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn read_exact_into<S: Read>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    length: usize,
) -> Result<(), ShatterError> {
    let mut chunk = [0u8; 1024];
    while buf.len() < length {
        let n = stream
            .read(&mut chunk)
            .map_err(|_| ShatterError::InvalidParameter)?;
        if n == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The `Content-Length` header among `lines`, or `None` if absent. A malformed value is an error.
fn content_length<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Option<usize>, ShatterError> {
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value
                    .trim()
                    .parse()
                    .map(Some)
                    .map_err(|_| ShatterError::InvalidParameter);
            }
        }
    }
    Ok(None)
}

/// A vault served by a `tpt-shatter-vault` process, used as a `VaultBackend`. Each call makes
/// one TLS connection. Any failure, including a refused certificate, is `VaultUnavailable`.
pub struct RemoteVault {
    vault: VaultId,
    addr: String,
    server_name: ServerName<'static>,
    tls: Arc<ClientConfig>,
}

impl RemoteVault {
    /// Targets the vault service at `addr` (`host:port`), expecting a certificate for
    /// `server_name`, and presenting the configuration in `tls`.
    pub fn new(
        vault: VaultId,
        addr: &str,
        server_name: &str,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, ShatterError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| ShatterError::InvalidParameter)?;
        Ok(Self {
            vault,
            addr: addr.to_owned(),
            server_name,
            tls,
        })
    }

    fn unavailable(&self) -> ShatterError {
        ShatterError::VaultUnavailable { vault: self.vault }
    }

    fn exchange(
        &self,
        method: &str,
        id: &FragmentId,
        body: &[u8],
    ) -> Result<Response, ShatterError> {
        let addr = self
            .addr
            .to_socket_addrs()
            .map_err(|_| self.unavailable())?
            .next()
            .ok_or_else(|| self.unavailable())?;
        let tcp = TcpStream::connect_timeout(&addr, IO_TIMEOUT).map_err(|_| self.unavailable())?;
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
        let conn = ClientConnection::new(Arc::clone(&self.tls), self.server_name.clone())
            .map_err(|_| self.unavailable())?;
        let mut stream = StreamOwned::new(conn, tcp);

        let head = format!(
            "{method} {FRAGMENT_PATH}{} HTTP/1.1\r\nHost: vault\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            hex(id.as_bytes()),
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .map_err(|_| self.unavailable())?;
        self.read_response(&mut stream)
    }

    fn read_response<S: Read>(&self, stream: &mut S) -> Result<Response, ShatterError> {
        let (head, mut body) =
            read_head_and_rest(stream, MAX_HEAD).map_err(|_| self.unavailable())?;
        let head = std::str::from_utf8(&head).map_err(|_| self.unavailable())?;
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| self.unavailable())?;
        let length = content_length(lines)
            .map_err(|_| self.unavailable())?
            .ok_or_else(|| self.unavailable())?;
        if length > MAX_BODY {
            return Err(self.unavailable());
        }
        read_exact_into(stream, &mut body, length).map_err(|_| self.unavailable())?;
        body.truncate(length);
        Ok(Response {
            status,
            body: Zeroizing::new(body),
            json: false,
        })
    }
}

impl VaultBackend for RemoteVault {
    fn vault(&self) -> VaultId {
        self.vault
    }

    fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
        match self.exchange("PUT", id, bytes)?.status {
            204 => Ok(()),
            _ => Err(self.unavailable()),
        }
    }

    fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
        let response = self.exchange("GET", id, &[])?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            _ => Err(self.unavailable()),
        }
    }

    fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
        let response = self.exchange("DELETE", id, &[])?;
        if response.status != 200 {
            return Err(self.unavailable());
        }
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|v| v["removed"].as_bool())
            .ok_or_else(|| self.unavailable())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests;
