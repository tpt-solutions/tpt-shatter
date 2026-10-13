// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The token issuer. Mints capability tokens for the host application.
//!
//! The host application authenticates the user upstream (out of scope here), then calls
//! `POST /v1/tokens` on the issuer's listener with the shard and the scopes it needs.
//!
//! Policy:
//! - Each caller presents a bearer secret. The config holds only its SHA-256. Every
//!   configured caller is compared on every request, so timing does not reveal which
//!   caller matched.
//! - Each caller has an allowed scope list and a maximum TTL. A request for anything else
//!   is `403`.
//! - `delete` is never issuable. Erasure is a maintenance operation, not a token.
//! - Every issuance is appended to a keyed audit chain on disk before the token is
//!   returned. If the append fails, the token is withheld (fail closed).
//!
//! Limit: the audit event records the token and shard digests, not the caller. The caller
//! name is in the access log, not in the chain.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response as HttpResponse, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tpt_shatter_common::{
    AuditAction, AuditChain, AuditEvent, AuditRecord, DEFAULT_TOKEN_TTL_SECS, Scope, Scopes,
    ShardKey, ShatterError, verify_chain,
};
use tpt_shatter_token::{MAX_TTL_SECS, Signer};
use tpt_shatter_vault_client::keyed_digest;

/// Largest request body the issuer accepts, in bytes.
const MAX_ISSUE_BODY: usize = 4 * 1024;

/// Token route.
const TOKEN_PATH: &str = "/v1/tokens";

/// One caller, as written in the config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerConfig {
    /// Name for the access log. Not secret.
    pub name: String,
    /// SHA-256 of the caller's bearer secret, as 64 hex characters.
    pub secret_sha256: String,
    /// Scopes this caller may request: any of `read` and `write`.
    pub scopes: Vec<String>,
    /// Longest TTL this caller may request, in seconds.
    pub max_ttl_secs: u64,
}

/// The issuer's configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// Address for the issuer listener. Keep it on an internal network.
    pub listen: String,
    /// The callers allowed to request tokens.
    pub callers: Vec<CallerConfig>,
}

/// A caller after its config has been checked.
struct Caller {
    name: String,
    secret_hash: [u8; 32],
    scopes: Scopes,
    max_ttl: u64,
}

/// The audit chain on disk. Every record is verified on open, and the chain resumes from
/// its last record.
pub struct AuditStore {
    state: Mutex<AuditState>,
    key: [u8; 32],
}

struct AuditState {
    chain: AuditChain,
    file: File,
    /// Set after a failed write. The in-memory chain is then ahead of the file, so no
    /// further record is accepted until the process restarts and reloads from the file.
    broken: bool,
}

impl AuditStore {
    /// Opens the log at `path`, verifies it under `key`, and resumes the chain.
    /// A log that fails verification refuses to open.
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, ShatterError> {
        let mut records = Vec::new();
        match File::open(path) {
            Ok(file) => {
                for line in BufReader::new(file).lines() {
                    let line = line.map_err(|_| ShatterError::Internal)?;
                    if !line.is_empty() {
                        records.push(AuditRecord::decode_line(&line)?);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ShatterError::Internal),
        }
        verify_chain(key, &records)?;
        let chain = AuditChain::resume(key, &records)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| ShatterError::Internal)?;
        Ok(Self {
            state: Mutex::new(AuditState {
                chain,
                file,
                broken: false,
            }),
            key,
        })
    }

    /// Appends one event and syncs it to disk before returning.
    pub fn record(&self, event: AuditEvent) -> Result<(), ShatterError> {
        let mut state = self.state.lock().map_err(|_| ShatterError::Internal)?;
        if state.broken {
            return Err(ShatterError::Internal);
        }
        let record = state.chain.append(event)?;
        let mut line = record.encode_line();
        line.push('\n');
        let written = state
            .file
            .write_all(line.as_bytes())
            .and_then(|()| state.file.sync_data());
        if written.is_err() {
            state.broken = true;
            return Err(ShatterError::Internal);
        }
        Ok(())
    }

    /// The key the chain is verified under.
    #[must_use]
    pub const fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// The outcome of one issue request: a status, a code for the access log, and a JSON body.
#[derive(Debug)]
pub struct IssueOutcome {
    /// HTTP status.
    pub status: u16,
    /// Stable code for the access log. Never a token or a secret.
    pub code: &'static str,
    /// Caller name when the secret matched, for the access log.
    pub caller: Option<String>,
    /// The JSON response body. On success it holds the token.
    pub body: Value,
}

/// Mints tokens under the policy above.
pub struct Issuer {
    signer: Arc<RwLock<Signer>>,
    callers: Vec<Caller>,
    audit: Arc<AuditStore>,
}

impl Issuer {
    /// Builds an issuer. Fails if a caller has a malformed hash, an unknown or
    /// non-issuable scope, or a zero or over-large maximum TTL.
    pub fn new(
        signer: Arc<RwLock<Signer>>,
        config: &IssuerConfig,
        audit: Arc<AuditStore>,
    ) -> Result<Self, ShatterError> {
        let callers = config
            .callers
            .iter()
            .map(parse_caller)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            signer,
            callers,
            audit,
        })
    }

    /// Handles one request: authenticate, check the body, apply the policy, issue, audit.
    ///
    /// `now` is Unix seconds. The token is returned only after its audit record is durable.
    pub fn issue(&self, bearer: &str, body: &[u8], now: u64) -> IssueOutcome {
        let Some(caller) = self.authenticate(bearer) else {
            return refused(401, "unauthorized", None);
        };
        let name = Some(caller.name.clone());
        let request = match parse_request(body) {
            Ok(request) => request,
            Err(()) => return refused(400, "bad_request", name),
        };
        let shard = match ShardKey::from_hex(&request.shard) {
            Ok(shard) => shard,
            Err(_) => return refused(400, "bad_request", name),
        };
        let scopes = match scopes_from(&request.scopes) {
            Ok(scopes) => scopes,
            Err(()) => return refused(400, "bad_request", name),
        };
        if !scopes_within(scopes, caller.scopes) {
            return refused(403, "forbidden", name);
        }
        let ttl = request.ttl_secs.unwrap_or(DEFAULT_TOKEN_TTL_SECS);
        if ttl == 0 || ttl > MAX_TTL_SECS {
            return refused(400, "bad_request", name);
        }
        if ttl > caller.max_ttl {
            return refused(403, "forbidden", name);
        }

        let token = match self.signer.read() {
            Ok(signer) => match signer.issue_with_ttl(&shard, scopes, now, ttl) {
                Ok(token) => token,
                Err(_) => return refused(500, "internal", name),
            },
            Err(_) => return refused(500, "internal", name),
        };
        let event = match self.event(token.as_bytes(), shard.as_bytes(), now) {
            Ok(event) => event,
            Err(_) => return refused(500, "internal", name),
        };
        // Fail closed: if the audit record is not durable, the token is not returned.
        if self.audit.record(event).is_err() {
            return refused(500, "internal", name);
        }
        IssueOutcome {
            status: 201,
            code: "issued",
            caller: name,
            body: json!({ "token": token.as_str(), "expires_at": now.saturating_add(ttl) }),
        }
    }

    /// Compares the presented secret with every caller, without an early exit.
    fn authenticate(&self, bearer: &str) -> Option<&Caller> {
        let presented = Sha256::digest(bearer.as_bytes());
        let mut matched = None;
        for caller in &self.callers {
            if constant_time_eq(&caller.secret_hash, &presented) {
                matched = Some(caller);
            }
        }
        matched
    }

    fn event(&self, token: &[u8], shard: &[u8], now: u64) -> Result<AuditEvent, ShatterError> {
        Ok(AuditEvent {
            action: AuditAction::Issue,
            token_digest: keyed_digest(self.audit.key(), b"tpt-shatter/issue/token", token)?,
            shard_digest: keyed_digest(self.audit.key(), b"tpt-shatter/issue/shard", shard)?,
            vault: None,
            at: now,
        })
    }
}

/// The fields of a token request, after the shape check.
struct TokenRequest {
    shard: String,
    scopes: Vec<String>,
    ttl_secs: Option<u64>,
}

fn parse_request(body: &[u8]) -> Result<TokenRequest, ()> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    for key in object.keys() {
        if !matches!(key.as_str(), "shard" | "scopes" | "ttl_secs") {
            return Err(());
        }
    }
    let shard = object
        .get("shard")
        .and_then(Value::as_str)
        .ok_or(())?
        .to_owned();
    let scopes = object
        .get("scopes")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(|s| s.as_str().map(str::to_owned).ok_or(()))
        .collect::<Result<Vec<_>, _>>()?;
    let ttl_secs = match object.get("ttl_secs") {
        None => None,
        Some(v) => Some(v.as_u64().ok_or(())?),
    };
    Ok(TokenRequest {
        shard,
        scopes,
        ttl_secs,
    })
}

/// Maps scope names to scopes. `delete` and unknown names are refused.
fn scopes_from(names: &[String]) -> Result<Scopes, ()> {
    if names.is_empty() {
        return Err(());
    }
    let mut scopes = Vec::with_capacity(names.len());
    for name in names {
        scopes.push(match name.as_str() {
            "read" => Scope::Read,
            "write" => Scope::Write,
            _ => return Err(()),
        });
    }
    Ok(Scopes::from_scopes(&scopes))
}

/// Whether every requested scope is also allowed to this caller.
fn scopes_within(requested: Scopes, allowed: Scopes) -> bool {
    requested.bits() & !allowed.bits() == 0
}

fn parse_caller(config: &CallerConfig) -> Result<Caller, ShatterError> {
    let secret_hash = parse_hex32(&config.secret_sha256)?;
    if config.max_ttl_secs == 0 || config.max_ttl_secs > MAX_TTL_SECS {
        return Err(ShatterError::InvalidParameter);
    }
    let names = config.scopes.clone();
    if names.iter().any(|n| n == "delete") {
        return Err(ShatterError::InvalidParameter);
    }
    let scopes = scopes_from(&names).map_err(|()| ShatterError::InvalidParameter)?;
    Ok(Caller {
        name: config.name.clone(),
        secret_hash,
        scopes,
        max_ttl: config.max_ttl_secs,
    })
}

fn parse_hex32(text: &str) -> Result<[u8; 32], ShatterError> {
    if text.len() != 64 || !text.is_ascii() {
        return Err(ShatterError::InvalidParameter);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| ShatterError::InvalidParameter)?;
    }
    Ok(out)
}

/// Equality over the whole array, with no early exit.
fn constant_time_eq(a: &[u8; 32], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0 && b.len() == a.len()
}

fn refused(status: u16, code: &'static str, caller: Option<String>) -> IssueOutcome {
    IssueOutcome {
        status,
        code,
        caller,
        body: json!({ "error": code }),
    }
}

/// Serves `POST /v1/tokens` on `listener`, over TLS when `acceptor` is given.
///
/// Other paths get `404`, and other methods `405`. Every response is JSON with
/// `Cache-Control: no-store`.
pub async fn serve_issuer(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    issuer: Arc<Issuer>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let issuer = Arc::clone(&issuer);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                None => serve_issuer_connection(stream, issuer).await,
                Some(acceptor) => {
                    if let Ok(Ok(tls)) =
                        tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await
                    {
                        serve_issuer_connection(tls, issuer).await;
                    }
                }
            }
        });
    }
}

async fn serve_issuer_connection<IO>(io: IO, issuer: Arc<Issuer>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let issuer = Arc::clone(&issuer);
        async move { Ok::<_, std::convert::Infallible>(route_issue(req, issuer).await) }
    });
    let _ = http1::Builder::new()
        .max_buf_size(8 * 1024)
        .serve_connection(TokioIo::new(io), service)
        .await;
}

async fn route_issue(req: Request<Incoming>, issuer: Arc<Issuer>) -> HttpResponse<Full<Bytes>> {
    if req.uri().path() != TOKEN_PATH {
        return json_response(StatusCode::NOT_FOUND, &json!({ "error": "not_found" }));
    }
    if req.method() != Method::POST {
        return json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({ "error": "method_not_allowed" }),
        );
    }
    let bearer = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_owned();
    let body = match Limited::new(req.into_body(), MAX_ISSUE_BODY)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.is::<LengthLimitError>() => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &json!({ "error": "too_large" }),
            );
        }
        Err(_) => {
            return json_response(StatusCode::BAD_REQUEST, &json!({ "error": "bad_request" }));
        }
    };
    let now = crate::now_secs();
    let outcome = match tokio::task::spawn_blocking(move || issuer.issue(&bearer, &body, now)).await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({ "error": "internal" }),
            );
        }
    };
    // The access log gets the caller name and the status. Never the body, which holds the token.
    eprintln!(
        "issuer: status={} code={} caller={}",
        outcome.status,
        outcome.code,
        outcome.caller.as_deref().unwrap_or("-")
    );
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response(status, &outcome.body)
}

fn json_response(status: StatusCode, body: &Value) -> HttpResponse<Full<Bytes>> {
    HttpResponse::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| HttpResponse::new(Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_HOST: &str = "host-app-secret-with-plenty-of-entropy";
    const SECRET_OTHER: &str = "another-caller-secret-value";
    const KEY: [u8; 32] = [0x9D; 32];
    const NOW: u64 = 1_800_000_000;

    fn sha_hex(text: &str) -> String {
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn caller(name: &str, secret: &str, scopes: &[&str], max_ttl: u64) -> CallerConfig {
        CallerConfig {
            name: name.to_owned(),
            secret_sha256: sha_hex(secret),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            max_ttl_secs: max_ttl,
        }
    }

    fn config() -> IssuerConfig {
        IssuerConfig {
            listen: "127.0.0.1:0".to_owned(),
            callers: vec![
                caller("host-app", SECRET_HOST, &["read"], 120),
                caller("writer", SECRET_OTHER, &["read", "write"], 60),
            ],
        }
    }

    fn temp_log(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-issuer-{name}-{nanos}.jsonl"))
    }

    fn issuer_at(path: &Path) -> Issuer {
        let signer = Arc::new(RwLock::new(Signer::new(1, [0x5E; 32])));
        let audit = AuditStore::open(path, KEY).expect("audit");
        Issuer::new(signer, &config(), Arc::new(audit)).expect("issuer")
    }

    fn body(shard: &str, scopes: &[&str], ttl: Option<u64>) -> Vec<u8> {
        let mut v = json!({ "shard": shard, "scopes": scopes });
        if let Some(t) = ttl {
            v["ttl_secs"] = json!(t);
        }
        v.to_string().into_bytes()
    }

    fn shard_hex() -> String {
        "3c".repeat(32)
    }

    #[test]
    fn a_valid_request_gets_a_token_that_the_signer_accepts() {
        let path = temp_log("valid");
        let issuer = issuer_at(&path);
        let outcome = issuer.issue(SECRET_HOST, &body(&shard_hex(), &["read"], Some(30)), NOW);
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(outcome.status, 201, "{outcome:?}");
        assert_eq!(outcome.body["expires_at"], json!(NOW + 30));
        let token = outcome.body["token"].as_str().expect("token");
        let shard = ShardKey::from_hex(&shard_hex()).expect("shard");
        let signer = issuer.signer.read().expect("lock");
        assert!(signer.authorize(token, &shard, Scope::Read, NOW).is_ok());
        assert!(
            signer.authorize(token, &shard, Scope::Write, NOW).is_err(),
            "scope stays narrow"
        );
    }

    #[test]
    fn wrong_secrets_are_unauthorized_and_uniform() {
        let path = temp_log("auth");
        let issuer = issuer_at(&path);
        let wrong = issuer.issue("not-a-secret", &body(&shard_hex(), &["read"], None), NOW);
        let empty = issuer.issue("", &body(&shard_hex(), &["read"], None), NOW);
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!((wrong.status, wrong.code), (401, "unauthorized"));
        assert_eq!(wrong.body, empty.body);
        assert!(wrong.caller.is_none());
    }

    #[test]
    fn a_caller_cannot_exceed_its_scopes_or_ttl() {
        let path = temp_log("policy");
        let issuer = issuer_at(&path);
        let write = issuer.issue(SECRET_HOST, &body(&shard_hex(), &["write"], None), NOW);
        let long = issuer.issue(SECRET_HOST, &body(&shard_hex(), &["read"], Some(200)), NOW);
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(write.status, 403, "host-app has no write scope");
        assert_eq!(long.status, 403, "host-app is capped at 120 seconds");
    }

    #[test]
    fn delete_and_unknown_scopes_are_never_issued() {
        let path = temp_log("scopes");
        let issuer = issuer_at(&path);
        let delete = issuer.issue(SECRET_OTHER, &body(&shard_hex(), &["delete"], None), NOW);
        let unknown = issuer.issue(SECRET_OTHER, &body(&shard_hex(), &["admin"], None), NOW);
        let none = issuer.issue(SECRET_OTHER, &body(&shard_hex(), &[], None), NOW);
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(delete.status, 400);
        assert_eq!(unknown.status, 400);
        assert_eq!(none.status, 400);
    }

    #[test]
    fn malformed_requests_are_refused_and_write_no_audit_record() {
        let path = temp_log("malformed");
        let issuer = issuer_at(&path);
        let cases = [
            b"not json".to_vec(),
            json!({"shard": shard_hex(), "scopes": ["read"], "extra": 1})
                .to_string()
                .into_bytes(),
            body("zz", &["read"], None),
            body(&shard_hex(), &["read"], Some(0)),
            body(&shard_hex(), &["read"], Some(MAX_TTL_SECS + 1)),
        ];
        let statuses: Vec<u16> = cases
            .iter()
            .map(|c| issuer.issue(SECRET_HOST, c, NOW).status)
            .collect();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::remove_file(&path).ok();
        assert!(statuses.iter().all(|s| *s == 400), "{statuses:?}");
        assert!(
            text.is_empty(),
            "a refused request must not reach the audit log"
        );
    }

    #[test]
    fn every_issuance_is_in_the_audit_chain_and_survives_a_restart() {
        let path = temp_log("audit");
        {
            let issuer = issuer_at(&path);
            for _ in 0..2 {
                assert_eq!(
                    issuer
                        .issue(SECRET_HOST, &body(&shard_hex(), &["read"], None), NOW)
                        .status,
                    201
                );
            }
        }
        let text = std::fs::read_to_string(&path).expect("read");
        let reopened = AuditStore::open(&path, KEY);
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(text.lines().count(), 2);
        assert!(
            !text.contains("tpt-shatter"),
            "no secret or token text in the log"
        );
        assert!(
            reopened.is_ok(),
            "the chain verifies and resumes after restart"
        );
    }

    #[test]
    fn a_tampered_audit_log_refuses_to_open() {
        let path = temp_log("tamper");
        issuer_at(&path).issue(SECRET_HOST, &body(&shard_hex(), &["read"], None), NOW);
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, text.replace(&format!("\"at\":{NOW}"), "\"at\":1")).expect("write");
        let result = AuditStore::open(&path, KEY).err();
        std::fs::remove_file(&path).expect("cleanup");
        assert!(result.is_some());
    }

    async fn exchange(addr: std::net::SocketAddr, raw: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.write_all(raw.as_bytes()).await.expect("write");
        let mut out = String::new();
        stream.read_to_string(&mut out).await.expect("read");
        out
    }

    #[tokio::test]
    async fn the_route_issues_on_post_and_refuses_other_methods_and_paths() {
        let path = temp_log("http");
        let issuer = Arc::new(issuer_at(&path));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve_issuer(listener, None, issuer));

        let payload = body(&shard_hex(), &["read"], None);
        let post = format!(
            "POST /v1/tokens HTTP/1.1\r\nHost: t\r\nConnection: close\r\nAuthorization: Bearer {SECRET_HOST}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            String::from_utf8_lossy(&payload)
        );
        let issued = exchange(addr, &post).await;
        let get = exchange(
            addr,
            "GET /v1/tokens HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        )
        .await;
        let other = exchange(
            addr,
            "POST /v1/other HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        std::fs::remove_file(&path).ok();

        assert!(issued.starts_with("HTTP/1.1 201"), "{issued}");
        assert!(issued.contains("\"token\""));
        assert!(get.starts_with("HTTP/1.1 405"), "{get}");
        assert!(other.starts_with("HTTP/1.1 404"), "{other}");
    }
}
