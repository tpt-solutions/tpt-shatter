// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, RwLock};

use sha2::{Digest, Sha256};
use tpt_shatter_common::{Alarm, CALLER_TAG_LEN, Record, Responder, Scope, ShardKey, ShatterError};
use tpt_shatter_token::Signer;

use crate::ratelimit::RateLimiter;

/// Supplies the next signing key: its version and bytes.
type NextKey = Box<dyn Fn() -> Result<(u32, [u8; 32]), ShatterError> + Send + Sync>;

/// Security notification for one alarm.
type Notify = Box<dyn Fn(&Alarm) -> Result<(), ShatterError> + Send + Sync>;

/// Supplies records for an authorized shard. The assembler will implement this.
pub trait RecordSource: Send + Sync {
    /// Reassembles the record for `shard`.
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError>;
}

impl<F> RecordSource for F
where
    F: Fn(&ShardKey) -> Result<Record, ShatterError> + Send + Sync,
{
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        self(shard)
    }
}

/// The outcome of a read, ready to be rendered by any transport.
///
/// `code` and `status` come from fixed tables. `fields` is set only on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP-style status code.
    pub status: u16,
    /// Stable machine-readable code, such as `ok` or `unauthorized`.
    pub code: &'static str,
    /// Record fields on success. Empty otherwise.
    pub fields: Vec<(String, String)>,
    /// Hex SHA-256 of the presented token. Safe to log.
    pub token_hash: String,
}

impl Response {
    /// One access-log line. It has the status, code, token hash, and field count. It never has token or field values.
    #[must_use]
    pub fn access_log_line(&self) -> String {
        format!(
            "status={} code={} token_hash={} fields={}",
            self.status,
            self.code,
            self.token_hash,
            self.fields.len()
        )
    }
}

/// Maps an internal error to a status and code that leak nothing.
///
/// All token failures (forged, expired, wrong scope, wrong shard) map to one
/// `401 unauthorized`, so a caller cannot tell them apart. A shard that is absent or
/// erased maps to the same `404` as any other missing shard.
#[must_use]
pub const fn public_error(error: ShatterError) -> (u16, &'static str) {
    match error {
        ShatterError::InvalidToken | ShatterError::TokenExpired | ShatterError::Unauthorized => {
            (401, "unauthorized")
        }
        // An unknown field name is the client's error on the write path.
        ShatterError::InvalidShardKey
        | ShatterError::InvalidParameter
        | ShatterError::InvalidSchema => (400, "bad_request"),
        ShatterError::Reconstruction => (404, "not_found"),
        ShatterError::RateLimited => (429, "rate_limited"),
        ShatterError::VaultUnavailable { .. } | ShatterError::ServiceUnavailable => {
            (503, "unavailable")
        }
        _ => (500, "internal"),
    }
}

/// Records an operation after it has been authorized and before it runs.
///
/// Called on the read and write paths once the token is verified. An error here stops the
/// operation, so nothing is read or stored without an audit record (fail closed).
pub trait AccessAudit: Send + Sync {
    /// Records an authorized `scope` operation on `shard` by `token` at `now` (Unix seconds).
    /// `caller` is the verified caller tag the token was issued under.
    fn authorized(
        &self,
        scope: Scope,
        token: &str,
        caller: &[u8; CALLER_TAG_LEN],
        shard: &ShardKey,
        now: u64,
    ) -> Result<(), ShatterError>;
}

/// The public read path.
pub struct Gateway<R: RecordSource> {
    signer: Arc<RwLock<Signer>>,
    source: R,
    limiter: Mutex<RateLimiter>,
    audit: Option<Arc<dyn AccessAudit>>,
}

impl<R: RecordSource> Gateway<R> {
    /// Creates a gateway that verifies tokens with `signer`, reads through `source`,
    /// and limits requests with `limiter`.
    #[must_use]
    pub fn new(signer: Arc<RwLock<Signer>>, source: R, limiter: RateLimiter) -> Self {
        Self {
            signer,
            source,
            limiter: Mutex::new(limiter),
            audit: None,
        }
    }

    /// Records every authorized read through `audit`.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AccessAudit>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Handles a read for `shard_hex` with `token` at `now_ms` (Unix milliseconds).
    ///
    /// Order: rate limit by token hash, parse the shard, verify the token against the
    /// shard with the `Read` scope, then fetch the record. Every failure becomes a
    /// [`Response`] with a uniform status and code.
    pub fn read(&self, token: &str, shard_hex: &str, now_ms: u64) -> Response {
        let digest = Sha256::digest(token.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        let token_hash = hex(&key);
        let result = self.run(token, key, shard_hex, now_ms);
        match result {
            Ok(fields) => Response {
                status: 200,
                code: "ok",
                fields,
                token_hash,
            },
            Err(error) => {
                let (status, code) = public_error(error);
                Response {
                    status,
                    code,
                    fields: Vec::new(),
                    token_hash,
                }
            }
        }
    }

    fn run(
        &self,
        token: &str,
        key: [u8; 32],
        shard_hex: &str,
        now_ms: u64,
    ) -> Result<Vec<(String, String)>, ShatterError> {
        self.limiter
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .check(key, now_ms)?;

        let shard = ShardKey::from_hex(shard_hex)?;
        let signer = self.signer.read().map_err(|_| ShatterError::Internal)?;
        let claims = signer.authorize(token, &shard, Scope::Read, now_ms / 1000)?;
        drop(signer);

        if let Some(audit) = &self.audit {
            audit.authorized(Scope::Read, token, claims.caller(), &shard, now_ms / 1000)?;
        }
        let record = self.source.fetch(&shard)?;
        Ok(record
            .field_names()
            .map(|name| (name.to_owned(), record.get(name).unwrap_or("").to_owned()))
            .collect())
    }
}

/// Rotates the signing key. Invoked by the canary responder, which invalidates every
/// outstanding token at once.
pub struct SigningKeyRotator {
    signer: Arc<RwLock<Signer>>,
    next_key: NextKey,
}

impl SigningKeyRotator {
    /// `next_key` supplies the next key version and bytes. Real provisioning is Phase 11.
    #[must_use]
    pub fn new(signer: Arc<RwLock<Signer>>, next_key: NextKey) -> Self {
        Self { signer, next_key }
    }

    fn rotate(&self) -> Result<(), ShatterError> {
        let (version, key) = (self.next_key)()?;
        self.signer
            .write()
            .map_err(|_| ShatterError::Internal)?
            .rotate(version, key);
        Ok(())
    }
}

/// Canary responder: rotates the key, then sends each alarm to `notify`.
pub struct AlarmResponder {
    rotator: SigningKeyRotator,
    notify: Notify,
}

impl AlarmResponder {
    /// Pairs a rotator with a security notification channel.
    #[must_use]
    pub fn new(rotator: SigningKeyRotator, notify: Notify) -> Self {
        Self { rotator, notify }
    }
}

impl Responder for AlarmResponder {
    fn rotate_signing_key(&self) -> Result<(), ShatterError> {
        self.rotator.rotate()
    }

    fn notify_security(&self, alarm: &Alarm) -> Result<(), ShatterError> {
        (self.notify)(alarm)
    }
}

/// Readiness: the gateway is ready when no vault breaker is open.
///
/// `breakers_open` holds one flag per vault, true when that vault's breaker is open.
/// The caller maps its vault statuses to flags, so the gateway needs no vault-client dependency.
#[must_use]
pub fn ready(breakers_open: &[bool]) -> bool {
    !breakers_open.iter().any(|open| *open)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_shatter_common::{DEFAULT_TOKEN_TTL_SECS, Scopes};

    type FixedSource = fn(&ShardKey) -> Result<Record, ShatterError>;

    const NOW_MS: u64 = 1_000_000_000;

    fn shard_hex() -> String {
        "07".repeat(32)
    }

    fn signer() -> Arc<RwLock<Signer>> {
        Arc::new(RwLock::new(Signer::new(1, [0xA5; 32])))
    }

    fn issue(signer: &Arc<RwLock<Signer>>, scopes: Scopes, now_secs: u64) -> String {
        let shard = ShardKey::from_bytes([7; 32]);
        let token = signer
            .read()
            .expect("lock")
            .issue(&shard, scopes, now_secs)
            .expect("issue");
        token.as_str().to_owned()
    }

    fn read_scope() -> Scopes {
        Scopes::from_scopes(&[Scope::Read])
    }

    fn record_source(shard: &ShardKey) -> Result<Record, ShatterError> {
        assert_eq!(shard.as_bytes(), &[7; 32]);
        let mut r = Record::new();
        r.insert("name", "A. Example");
        r.insert("birth_year", "1990");
        Ok(r)
    }

    fn gateway(signer: &Arc<RwLock<Signer>>, limit: u32) -> Gateway<FixedSource> {
        let source: FixedSource = record_source;
        Gateway::new(
            Arc::clone(signer),
            source,
            RateLimiter::new(limit, 1, 100).expect("limiter"),
        )
    }

    struct RefusingAudit;

    impl AccessAudit for RefusingAudit {
        fn authorized(
            &self,
            _: Scope,
            _: &str,
            _: &[u8; CALLER_TAG_LEN],
            _: &ShardKey,
            _: u64,
        ) -> Result<(), ShatterError> {
            Err(ShatterError::Internal)
        }
    }

    #[test]
    fn a_read_the_audit_cannot_record_is_refused_before_the_fetch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let fetches = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fetches);
        let source = move |shard: &ShardKey| {
            counter.fetch_add(1, Ordering::SeqCst);
            record_source(shard)
        };
        let gw = Gateway::new(
            Arc::clone(&s),
            source,
            RateLimiter::new(10, 1, 100).expect("limiter"),
        )
        .with_audit(Arc::new(RefusingAudit));

        let resp = gw.read(&token, &shard_hex(), NOW_MS);
        assert_eq!(resp.status, 500, "{resp:?}");
        assert!(resp.fields.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_token_returns_the_record() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let resp = gateway(&s, 10).read(&token, &shard_hex(), NOW_MS);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.code, "ok");
        assert_eq!(resp.fields.len(), 2);
        assert!(
            resp.fields
                .contains(&("name".to_owned(), "A. Example".to_owned()))
        );
    }

    #[test]
    fn every_token_failure_looks_the_same() {
        let s = signer();
        let now = NOW_MS / 1000;
        let gw = gateway(&s, 100);
        let forged = {
            let mut t = issue(&s, read_scope(), now);
            t.push('A');
            t
        };
        let expired = issue(&s, read_scope(), now - DEFAULT_TOKEN_TTL_SECS - 10);
        let no_scope = issue(&s, Scopes::from_scopes(&[Scope::Write]), now);

        let cases = [
            forged.as_str(),
            expired.as_str(),
            no_scope.as_str(),
            "garbage",
        ];
        for token in cases {
            let resp = gw.read(token, &shard_hex(), NOW_MS);
            assert_eq!(
                (resp.status, resp.code),
                (401, "unauthorized"),
                "token {token:.8}"
            );
            assert!(resp.fields.is_empty());
        }
    }

    #[test]
    fn token_for_a_different_shard_is_unauthorized() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let resp = gateway(&s, 10).read(&token, &"08".repeat(32), NOW_MS);
        assert_eq!((resp.status, resp.code), (401, "unauthorized"));
    }

    #[test]
    fn malformed_shard_is_a_bad_request() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let resp = gateway(&s, 10).read(&token, "not-hex", NOW_MS);
        assert_eq!((resp.status, resp.code), (400, "bad_request"));
    }

    #[test]
    fn missing_record_is_not_found() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let source: fn(&ShardKey) -> Result<Record, ShatterError> =
            |_| Err(ShatterError::Reconstruction);
        let gw = Gateway::new(
            Arc::clone(&s),
            source,
            RateLimiter::new(10, 1, 10).expect("l"),
        );
        let resp = gw.read(&token, &shard_hex(), NOW_MS);
        assert_eq!((resp.status, resp.code), (404, "not_found"));
    }

    #[test]
    fn vault_outage_is_unavailable() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let source: fn(&ShardKey) -> Result<Record, ShatterError> = |_| {
            Err(ShatterError::VaultUnavailable {
                vault: tpt_shatter_common::VaultId::A,
            })
        };
        let gw = Gateway::new(
            Arc::clone(&s),
            source,
            RateLimiter::new(10, 1, 10).expect("l"),
        );
        let resp = gw.read(&token, &shard_hex(), NOW_MS);
        assert_eq!((resp.status, resp.code), (503, "unavailable"));
    }

    #[test]
    fn repeated_requests_are_rate_limited_per_token() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let gw = gateway(&s, 2);
        assert_eq!(gw.read(&token, &shard_hex(), NOW_MS).status, 200);
        assert_eq!(gw.read(&token, &shard_hex(), NOW_MS).status, 200);
        assert_eq!(gw.read(&token, &shard_hex(), NOW_MS).status, 429);
    }

    #[test]
    fn rotation_invalidates_outstanding_tokens() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let gw = gateway(&s, 10);
        assert_eq!(gw.read(&token, &shard_hex(), NOW_MS).status, 200);

        let rotator = SigningKeyRotator::new(Arc::clone(&s), Box::new(|| Ok((2, [0xB6; 32]))));
        let responder = AlarmResponder::new(rotator, Box::new(|_| Ok(())));
        responder.rotate_signing_key().expect("rotate");

        let resp = gw.read(&token, &shard_hex(), NOW_MS);
        assert_eq!((resp.status, resp.code), (401, "unauthorized"));
    }

    #[test]
    fn alarm_notifies_security_for_each_alarm() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let s = signer();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let rotator = SigningKeyRotator::new(Arc::clone(&s), Box::new(|| Ok((2, [0xC7; 32]))));
        let responder = AlarmResponder::new(
            rotator,
            Box::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        let alarm = Alarm {
            vault: tpt_shatter_common::VaultId::B,
            index: 0,
        };
        responder.notify_security(&alarm).expect("notify");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn access_log_never_contains_the_token_or_values() {
        let s = signer();
        let token = issue(&s, read_scope(), NOW_MS / 1000);
        let resp = gateway(&s, 10).read(&token, &shard_hex(), NOW_MS);
        let line = resp.access_log_line();
        assert!(line.contains("status=200"));
        assert!(!line.contains(&token));
        assert!(!line.contains("A. Example"));
        assert_eq!(resp.token_hash.len(), 64);
    }

    #[test]
    fn readiness_is_false_while_a_breaker_is_open() {
        assert!(ready(&[false, false, false]));
        assert!(!ready(&[false, true, false]));
    }
}
