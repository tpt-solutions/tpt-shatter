// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The analytics feed. Each accepted write is anonymized and held until the k-anonymity
//! gate passes. Then it goes to the strata sink. Only anonymized events are held, never
//! the raw record.
//!
//! Retention: an event leaves the hold, and the sink, once it is older than the node's
//! retention window. So an event still held when its window ends is dropped unemitted.
//!
//! Policy file (JSON), with the salt read from the environment:
//!
//! ```json
//! {
//!   "k": 10,
//!   "quasi_identifiers": ["birth_year"],
//!   "rules": {
//!     "name": "pseudonymize",
//!     "birth_year": {"bucket": {"width": 10}},
//!     "card_number": {"mask": {"keep_last": 4}},
//!     "ssn": "drop"
//!   }
//! }
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use serde::Deserialize;
use tpt_shatter_common::{Record, ShatterError};
use tpt_shatter_emitter::{Emitter, Event, Policy, StrataSink, Transform};

/// One rule as written in the policy file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum RuleFile {
    Drop,
    Pseudonymize,
    Mask { keep_last: usize },
    Bucket { width: i64 },
    Noise { sensitivity: f64, epsilon: f64 },
}

/// The policy file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    k: usize,
    quasi_identifiers: Vec<String>,
    rules: BTreeMap<String, RuleFile>,
}

/// Loads a policy file, keyed with `salt`. Fails on any unknown field or invalid rule.
pub fn load_policy(path: &Path, salt: &[u8]) -> Result<Policy, ShatterError> {
    let text = fs::read_to_string(path).map_err(|_| ShatterError::InvalidSchema)?;
    let file: PolicyFile = serde_json::from_str(&text).map_err(|_| ShatterError::InvalidSchema)?;
    let rules = file.rules.into_iter().map(|(name, rule)| {
        let transform = match rule {
            RuleFile::Drop => Transform::Drop,
            RuleFile::Pseudonymize => Transform::Pseudonymize,
            RuleFile::Mask { keep_last } => Transform::Mask { keep_last },
            RuleFile::Bucket { width } => Transform::Bucket { width },
            RuleFile::Noise {
                sensitivity,
                epsilon,
            } => Transform::Noise {
                sensitivity,
                epsilon,
            },
        };
        (name, transform)
    });
    Policy::new(salt.to_vec(), rules, file.quasi_identifiers, file.k)
}

/// The analytics feed for one node.
pub struct Analytics {
    emitter: Emitter<StrataSink>,
    /// Anonymized events not yet emitted, each with the time it was accepted.
    held: Mutex<Vec<(u64, Event)>>,
    retention_secs: u64,
}

impl Analytics {
    /// Opens the strata sink at `log` and pairs it with `policy`.
    pub fn open(policy: Policy, log: &Path, retention_secs: u64) -> Result<Self, ShatterError> {
        if retention_secs == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self {
            emitter: Emitter::new(policy, StrataSink::open(log)?),
            held: Mutex::new(Vec::new()),
            retention_secs,
        })
    }

    /// Anonymizes `record` without holding it. The caller holds the result only after the
    /// record is stored, so an analytics event never exists for a write that failed.
    pub fn prepare(&self, record: &Record) -> Result<Vec<Event>, ShatterError> {
        self.emitter.anonymize(std::slice::from_ref(record))
    }

    /// Holds prepared events, timestamped `now` (Unix seconds).
    pub fn hold(&self, events: Vec<Event>, now: u64) -> Result<(), ShatterError> {
        let mut held = self.held.lock().map_err(|_| ShatterError::Internal)?;
        held.extend(events.into_iter().map(|event| (now, event)));
        Ok(())
    }

    /// Emits the held events if the k-anonymity gate passes over all of them. If it does
    /// not, they stay held. Events older than the retention window are dropped first.
    /// Returns how many events were emitted.
    pub fn flush(&self, now: u64) -> Result<usize, ShatterError> {
        let mut held = self.held.lock().map_err(|_| ShatterError::Internal)?;
        let cutoff = now.saturating_sub(self.retention_secs);
        held.retain(|(at, _)| *at >= cutoff);
        if held.is_empty() {
            return Ok(0);
        }
        let events: Vec<Event> = held.iter().map(|(_, e)| e.clone()).collect();
        match self.emitter.check_k(&events) {
            Ok(()) => {}
            Err(ShatterError::KAnonymityViolation) => return Ok(0),
            Err(e) => return Err(e),
        }
        self.emitter.sink().append(&held)?;
        let emitted = held.len();
        held.clear();
        Ok(emitted)
    }

    /// Erases emitted events older than the retention window. Returns how many were erased.
    pub fn purge(&self, now: u64) -> Result<usize, ShatterError> {
        self.emitter
            .sink()
            .purge_before(now.saturating_sub(self.retention_secs))
    }
}
