// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! HTTP/1.1 transport for the gateway, built on hyper (MIT).
//!
//! Routes:
//! - `GET /healthz` is liveness and always returns 200.
//! - `GET /readyz` returns 200 when no vault breaker is open, otherwise 503.
//! - `GET /v1/records/{shard_hex}` reads a record. The capability token goes in
//!   `Authorization: Bearer <token>`.
//!
//! Every response is JSON with `Cache-Control: no-store`. Errors are `{"error": code}`
//! using the same codes as [`Response::code`](crate::Response). Access logs use
//! [`Response::access_log_line`], so they never contain tokens or field values.
//!
//! Plain HTTP is served by [`serve`]. For TLS 1.3 (and optional mTLS), use
//! [`serve_tls`] with an acceptor from [`crate::acceptor`]. See `DECISIONS.md`.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response as HttpResponse, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::service::{Gateway, RecordSource, Response, ready};

/// Tunables for the HTTP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConfig {
    /// Upper bound on handling one request, including the vault read.
    pub request_timeout: Duration,
    /// Maximum size of the request head (request line and headers).
    pub max_header_bytes: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            max_header_bytes: 8 * 1024,
        }
    }
}

/// Reports one open-breaker flag per vault, true when that vault's breaker is open.
pub type BreakerProbe = Arc<dyn Fn() -> Vec<bool> + Send + Sync>;

/// Receives one access-log line per request. Lines hold no tokens or field values.
pub type AccessLog = Arc<dyn Fn(&str) + Send + Sync>;

/// Shared state for every connection.
pub struct Shared<R: RecordSource + 'static> {
    /// The gateway that performs reads.
    pub gateway: Arc<Gateway<R>>,
    /// Source of breaker flags for `/readyz`.
    pub breakers: BreakerProbe,
    /// Destination for access-log lines.
    pub access_log: AccessLog,
    /// HTTP tunables.
    pub config: HttpConfig,
}

/// Serves connections on `listener` until the listener fails.
///
/// Each connection runs on its own task. Reads run on the blocking pool, since
/// [`Gateway::read`] is synchronous.
pub async fn serve<R: RecordSource + 'static>(
    listener: TcpListener,
    shared: Arc<Shared<R>>,
) -> std::io::Result<()> {
    accept_loop(listener, shared, None).await
}

/// Like [`serve`], but every connection completes a TLS handshake first.
///
/// The handshake shares the request timeout, so a client that stalls mid-handshake
/// is dropped rather than holding a task open.
pub async fn serve_tls<R: RecordSource + 'static>(
    listener: TcpListener,
    shared: Arc<Shared<R>>,
    acceptor: TlsAcceptor,
) -> std::io::Result<()> {
    accept_loop(listener, shared, Some(acceptor)).await
}

async fn accept_loop<R: RecordSource + 'static>(
    listener: TcpListener,
    shared: Arc<Shared<R>>,
    acceptor: Option<TlsAcceptor>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                None => serve_connection(stream, shared).await,
                Some(acceptor) => {
                    let timeout = shared.config.request_timeout;
                    if let Ok(Ok(tls)) =
                        tokio::time::timeout(timeout, acceptor.accept(stream)).await
                    {
                        serve_connection(tls, shared).await;
                    }
                }
            }
        });
    }
}

async fn serve_connection<R, IO>(io: IO, shared: Arc<Shared<R>>)
where
    R: RecordSource + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_buf = shared.config.max_header_bytes;
    let service = service_fn(move |req| {
        let shared = Arc::clone(&shared);
        async move { Ok::<_, Infallible>(route(req, shared).await) }
    });
    let _ = http1::Builder::new()
        .max_buf_size(max_buf)
        .serve_connection(TokioIo::new(io), service)
        .await;
}

async fn route<R: RecordSource + 'static>(
    req: Request<Incoming>,
    shared: Arc<Shared<R>>,
) -> HttpResponse<Full<Bytes>> {
    let timeout = shared.config.request_timeout;
    match tokio::time::timeout(timeout, dispatch(req, &shared)).await {
        Ok(response) => response,
        Err(_) => error_body(StatusCode::SERVICE_UNAVAILABLE, "timeout"),
    }
}

async fn dispatch<R: RecordSource + 'static>(
    req: Request<Incoming>,
    shared: &Shared<R>,
) -> HttpResponse<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    if req.method() != Method::GET {
        return error_body(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    }
    match path.as_str() {
        "/healthz" => json_body(StatusCode::OK, &json!({ "status": "live" })),
        "/readyz" => {
            let flags = (shared.breakers)();
            if ready(&flags) {
                json_body(StatusCode::OK, &json!({ "status": "ready" }))
            } else {
                error_body(StatusCode::SERVICE_UNAVAILABLE, "not_ready")
            }
        }
        _ => match path.strip_prefix("/v1/records/") {
            Some(shard_hex) => read_record(req.headers(), shard_hex, shared).await,
            None => error_body(StatusCode::NOT_FOUND, "not_found"),
        },
    }
}

async fn read_record<R: RecordSource + 'static>(
    headers: &hyper::HeaderMap,
    shard_hex: &str,
    shared: &Shared<R>,
) -> HttpResponse<Full<Bytes>> {
    // A missing or malformed header is treated as an empty token, so it gets the same
    // uniform 401 as a forged token.
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_owned();
    let shard_hex = shard_hex.to_owned();
    let now_ms = now_millis();
    let gateway = Arc::clone(&shared.gateway);
    let result =
        tokio::task::spawn_blocking(move || gateway.read(&token, &shard_hex, now_ms)).await;
    match result {
        Ok(response) => {
            (shared.access_log)(&response.access_log_line());
            render(&response)
        }
        Err(_) => error_body(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn render(response: &Response) -> HttpResponse<Full<Bytes>> {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if response.status == 200 {
        let fields: serde_json::Map<String, serde_json::Value> = response
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        json_body(status, &json!({ "fields": fields }))
    } else {
        error_body(status, response.code)
    }
}

fn error_body(status: StatusCode, code: &str) -> HttpResponse<Full<Bytes>> {
    json_body(status, &json!({ "error": code }))
}

fn json_body(status: StatusCode, value: &serde_json::Value) -> HttpResponse<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    HttpResponse::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| HttpResponse::new(Full::new(Bytes::new())))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tpt_shatter_common::{Record, ShardKey, ShatterError};
    use tpt_shatter_token::Signer;

    use super::*;
    use crate::ratelimit::RateLimiter;

    fn source(_: &ShardKey) -> Result<Record, ShatterError> {
        Err(ShatterError::Reconstruction)
    }

    type Source = fn(&ShardKey) -> Result<Record, ShatterError>;

    async fn start(breakers_open: Vec<bool>, log: Arc<Mutex<Vec<String>>>) -> std::net::SocketAddr {
        let signer = Arc::new(std::sync::RwLock::new(Signer::new(1, [0xA5; 32])));
        let source: Source = source;
        let gateway = Gateway::new(
            signer,
            source,
            RateLimiter::new(100, 1, 100).expect("limiter"),
        );
        let shared = Arc::new(Shared {
            gateway: Arc::new(gateway),
            breakers: Arc::new(move || breakers_open.clone()),
            access_log: Arc::new(move |line: &str| {
                log.lock().expect("log").push(line.to_owned());
            }),
            config: HttpConfig::default(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(listener, shared));
        addr
    }

    async fn request(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(raw.as_bytes()).await.expect("write");
        let mut out = String::new();
        stream.read_to_string(&mut out).await.expect("read");
        out
    }

    fn get(path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{extra}\r\n")
    }

    #[tokio::test]
    async fn liveness_is_always_ok() {
        let addr = start(vec![true], Arc::new(Mutex::new(Vec::new()))).await;
        let out = request(addr, &get("/healthz", "")).await;
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains(r#"{"status":"live"}"#));
    }

    #[tokio::test]
    async fn readiness_reflects_breakers() {
        let ok = start(vec![false, false, false], Arc::new(Mutex::new(Vec::new()))).await;
        assert!(
            request(ok, &get("/readyz", ""))
                .await
                .starts_with("HTTP/1.1 200")
        );
        let open = start(vec![false, true, false], Arc::new(Mutex::new(Vec::new()))).await;
        let out = request(open, &get("/readyz", "")).await;
        assert!(out.starts_with("HTTP/1.1 503"), "{out}");
        assert!(out.contains(r#"{"error":"not_ready"}"#));
    }

    #[tokio::test]
    async fn missing_token_gets_uniform_unauthorized() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let addr = start(vec![false], Arc::clone(&log)).await;
        let out = request(addr, &get(&format!("/v1/records/{}", "07".repeat(32)), "")).await;
        assert!(out.starts_with("HTTP/1.1 401"), "{out}");
        assert!(out.contains(r#"{"error":"unauthorized"}"#));
        assert!(out.contains("cache-control: no-store") || out.contains("Cache-Control: no-store"));
        let lines = log.lock().expect("log");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("code=unauthorized"));
    }

    #[tokio::test]
    async fn unknown_route_and_wrong_method_are_rejected() {
        let addr = start(vec![false], Arc::new(Mutex::new(Vec::new()))).await;
        assert!(
            request(addr, &get("/nope", ""))
                .await
                .starts_with("HTTP/1.1 404")
        );
        let post = "POST /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        assert!(request(addr, post).await.starts_with("HTTP/1.1 405"));
    }

    #[tokio::test]
    async fn oversized_head_is_refused() {
        let addr = start(vec![false], Arc::new(Mutex::new(Vec::new()))).await;
        let big = "x".repeat(16 * 1024);
        let out = request(addr, &get("/healthz", &format!("X-Big: {big}\r\n"))).await;
        assert!(
            !out.starts_with("HTTP/1.1 200"),
            "{}",
            &out[..out.len().min(80)]
        );
    }
}
