// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The write path: stores a record under a shard, behind the same token and rate-limit
//! checks as reads.
//!
//! A write needs a token with the `Write` scope for the shard. Tokens for reads cannot
//! write, and the reverse. Every failure becomes a [`Response`] with a uniform status and
//! code, as on the read path. A response never contains the record.

use std::sync::{Arc, Mutex, RwLock};

use sha2::{Digest, Sha256};
use tpt_shatter_common::{Record, Scope, ShardKey, ShatterError};
use tpt_shatter_token::Signer;

use crate::ratelimit::RateLimiter;
use crate::service::{AccessAudit, Response, hex, public_error};

/// Stores a record under a shard. A node implements it over the shredder.
pub trait RecordSink: Send + Sync {
    /// Shreds and stores `record` under `shard`.
    fn store(&self, shard: &ShardKey, record: Record) -> Result<(), ShatterError>;
}

impl<F> RecordSink for F
where
    F: Fn(&ShardKey, Record) -> Result<(), ShatterError> + Send + Sync,
{
    fn store(&self, shard: &ShardKey, record: Record) -> Result<(), ShatterError> {
        self(shard, record)
    }
}

/// Handles writes. Mirrors `Gateway` for reads.
pub struct Writer<S: RecordSink> {
    signer: Arc<RwLock<Signer>>,
    sink: S,
    limiter: Mutex<RateLimiter>,
    audit: Option<Arc<dyn AccessAudit>>,
}

impl<S: RecordSink> Writer<S> {
    /// Creates a writer that verifies tokens with `signer`, stores through `sink`, and
    /// limits requests with `limiter`.
    #[must_use]
    pub fn new(signer: Arc<RwLock<Signer>>, sink: S, limiter: RateLimiter) -> Self {
        Self {
            signer,
            sink,
            limiter: Mutex::new(limiter),
            audit: None,
        }
    }

    /// Records every authorized write through `audit`, before the record is stored.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AccessAudit>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Stores `fields` under `shard_hex`, authorized by `token`, at `now_ms`.
    ///
    /// Success is `201` with code `created` and no fields. A field name that appears
    /// twice is refused as a bad request, since a record cannot hold two values for one name.
    pub fn write(
        &self,
        token: &str,
        shard_hex: &str,
        fields: &[(String, String)],
        now_ms: u64,
    ) -> Response {
        let digest = Sha256::digest(token.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        let token_hash = hex(&key);
        match self.run(token, key, shard_hex, fields, now_ms) {
            Ok(()) => Response {
                status: 201,
                code: "created",
                fields: Vec::new(),
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
        fields: &[(String, String)],
        now_ms: u64,
    ) -> Result<(), ShatterError> {
        self.limiter
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .check(key, now_ms)?;

        let shard = ShardKey::from_hex(shard_hex)?;
        let signer = self.signer.read().map_err(|_| ShatterError::Internal)?;
        let claims = signer.authorize(token, &shard, Scope::Write, now_ms / 1000)?;
        drop(signer);

        let mut record = Record::new();
        for (name, value) in fields {
            if record.insert(name.as_str(), value.as_str()).is_some() {
                return Err(ShatterError::InvalidParameter);
            }
        }
        if let Some(audit) = &self.audit {
            audit.authorized(Scope::Write, token, claims.caller(), &shard, now_ms / 1000)?;
        }
        self.sink.store(&shard, record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tpt_shatter_common::{DEFAULT_TOKEN_TTL_SECS, Scopes};

    const NOW_MS: u64 = 1_000_000_000;
    const SHARD: [u8; 32] = [7; 32];

    fn signer() -> Arc<RwLock<Signer>> {
        Arc::new(RwLock::new(Signer::new(1, [0xB4; 32])))
    }

    fn issue(signer: &Arc<RwLock<Signer>>, scope: Scope, now_secs: u64) -> String {
        signer
            .read()
            .expect("lock")
            .issue(
                &ShardKey::from_bytes(SHARD),
                Scopes::from_scopes(&[scope]),
                now_secs,
            )
            .expect("issue")
            .as_str()
            .to_owned()
    }

    fn shard_hex() -> String {
        "07".repeat(32)
    }

    fn fields() -> Vec<(String, String)> {
        vec![("name".to_owned(), "A. Example".to_owned())]
    }

    type Stored = Arc<StdMutex<Vec<usize>>>;

    /// A sink that remembers what it was asked to store, and how many fields.
    fn recording_sink(stored: &Stored) -> impl RecordSink {
        let stored = Arc::clone(stored);
        move |shard: &ShardKey, record: Record| {
            let _ = shard;
            stored.lock().expect("lock").push(record.len());
            Ok(())
        }
    }

    #[test]
    fn a_write_token_stores_the_record_and_answers_created() {
        let s = signer();
        let stored: Stored = Arc::default();
        let writer = Writer::new(
            Arc::clone(&s),
            recording_sink(&stored),
            RateLimiter::new(10, 1, 100).expect("limiter"),
        );
        let token = issue(&s, Scope::Write, NOW_MS / 1000);
        let resp = writer.write(&token, &shard_hex(), &fields(), NOW_MS);
        assert_eq!(resp.status, 201, "{resp:?}");
        assert_eq!(resp.code, "created");
        assert!(resp.fields.is_empty(), "a write never echoes the record");
        assert_eq!(stored.lock().expect("lock").len(), 1);
        assert_eq!(stored.lock().expect("lock")[0], 1);
    }

    #[test]
    fn a_read_token_cannot_write() {
        let s = signer();
        let stored: Stored = Arc::default();
        let writer = Writer::new(
            Arc::clone(&s),
            recording_sink(&stored),
            RateLimiter::new(10, 1, 100).expect("limiter"),
        );
        let token = issue(&s, Scope::Read, NOW_MS / 1000);
        let resp = writer.write(&token, &shard_hex(), &fields(), NOW_MS);
        assert_eq!(resp.status, 401);
        assert!(stored.lock().expect("lock").is_empty());
    }

    #[test]
    fn an_expired_write_token_is_refused() {
        let s = signer();
        let stored: Stored = Arc::default();
        let writer = Writer::new(
            Arc::clone(&s),
            recording_sink(&stored),
            RateLimiter::new(10, 1, 100).expect("limiter"),
        );
        let token = issue(
            &s,
            Scope::Write,
            NOW_MS / 1000 - DEFAULT_TOKEN_TTL_SECS - 10,
        );
        assert_eq!(
            writer.write(&token, &shard_hex(), &fields(), NOW_MS).status,
            401
        );
    }

    #[test]
    fn duplicate_field_names_are_a_bad_request() {
        let s = signer();
        let stored: Stored = Arc::default();
        let writer = Writer::new(
            Arc::clone(&s),
            recording_sink(&stored),
            RateLimiter::new(10, 1, 100).expect("limiter"),
        );
        let token = issue(&s, Scope::Write, NOW_MS / 1000);
        let dup = vec![
            ("name".to_owned(), "one".to_owned()),
            ("name".to_owned(), "two".to_owned()),
        ];
        let resp = writer.write(&token, &shard_hex(), &dup, NOW_MS);
        assert_eq!(resp.status, 400);
        assert!(stored.lock().expect("lock").is_empty());
    }

    #[test]
    fn a_sink_refusal_is_reported_without_detail() {
        let s = signer();
        let writer = Writer::new(
            Arc::clone(&s),
            |_: &ShardKey, _: Record| Err(ShatterError::InvalidSchema),
            RateLimiter::new(10, 1, 100).expect("limiter"),
        );
        let token = issue(&s, Scope::Write, NOW_MS / 1000);
        let resp = writer.write(&token, &shard_hex(), &fields(), NOW_MS);
        assert_eq!(resp.status, 400);
        assert_eq!(resp.code, "bad_request");
        assert!(!resp.access_log_line().contains("A. Example"));
    }
}
