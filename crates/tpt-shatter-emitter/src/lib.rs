// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Anonymizes reconstructed records and emits them to an analytics sink.
//!
//! The [`Policy`] decides what happens to each field. A field with no rule is dropped,
//! so unexpected fields never reach the sink. Before anything is emitted, the
//! k-anonymity gate checks the quasi-identifier cohorts of the whole batch. If any
//! cohort is too small, the whole batch is refused.
//!
//! The sink is a trait. The real tpt-strata adapter is not written yet, because its
//! ingest API has not been verified (see UPSTREAM.md).

mod strata;

pub use strata::StrataSink;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;

use tpt_shatter_anonymize::{add_noise, bucket, check_k_anonymity, mask, pseudonymize};
use tpt_shatter_common::{Record, ShatterError};
use zeroize::Zeroizing;

/// What happens to one field on its way out.
#[derive(Debug, Clone, PartialEq)]
pub enum Transform {
    /// Remove the field entirely.
    Drop,
    /// Show only the last `keep_last` characters, masking the rest.
    Mask {
        /// Characters to leave visible at the end.
        keep_last: usize,
    },
    /// Replace an integer with its `width`-wide range, such as `1990-1999`.
    Bucket {
        /// Range width. Must be positive.
        width: i64,
    },
    /// Replace the value with a salted SHA-256 digest, in lowercase hex.
    Pseudonymize,
    /// Add Laplace noise with scale `sensitivity / epsilon`, to a numeric value.
    Noise {
        /// L1 sensitivity of the value.
        sensitivity: f64,
        /// Privacy budget. Must be positive.
        epsilon: f64,
    },
}

/// The anonymization policy for one emitter.
pub struct Policy {
    salt: Zeroizing<Vec<u8>>,
    rules: BTreeMap<String, Transform>,
    quasi_identifiers: Vec<String>,
    k: usize,
}

impl Policy {
    /// Builds a policy.
    ///
    /// Returns [`ShatterError::InvalidParameter`] if the salt is empty, `k` is zero, a
    /// quasi-identifier has no rule or is dropped, or a bucket width is not positive.
    pub fn new(
        salt: Vec<u8>,
        rules: impl IntoIterator<Item = (String, Transform)>,
        quasi_identifiers: Vec<String>,
        k: usize,
    ) -> Result<Self, ShatterError> {
        let salt = Zeroizing::new(salt);
        if salt.is_empty() || k == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        let rules: BTreeMap<String, Transform> = rules.into_iter().collect();
        for transform in rules.values() {
            if let Transform::Bucket { width } = transform {
                if *width <= 0 {
                    return Err(ShatterError::InvalidParameter);
                }
            }
        }
        for qi in &quasi_identifiers {
            match rules.get(qi) {
                Some(Transform::Drop) | None => return Err(ShatterError::InvalidParameter),
                Some(_) => {}
            }
        }
        Ok(Self {
            salt,
            rules,
            quasi_identifiers,
            k,
        })
    }

    /// Anonymizes one record. Fields without a rule are omitted.
    pub fn transform(&self, record: &Record) -> Result<Event, ShatterError> {
        let mut fields = BTreeMap::new();
        for name in record.field_names() {
            let Some(rule) = self.rules.get(name) else {
                continue;
            };
            let value = record.get(name).ok_or(ShatterError::Internal)?;
            if let Some(out) = self.apply(rule, value)? {
                fields.insert(name.to_owned(), out);
            }
        }
        Ok(Event { fields })
    }

    fn apply(&self, rule: &Transform, value: &str) -> Result<Option<String>, ShatterError> {
        Ok(match rule {
            Transform::Drop => None,
            Transform::Mask { keep_last } => Some(mask(value, *keep_last)),
            Transform::Bucket { width } => {
                let n: i64 = value.parse().map_err(|_| ShatterError::InvalidParameter)?;
                Some(bucket(n, *width)?.to_string())
            }
            Transform::Pseudonymize => Some(hex(&pseudonymize(&self.salt, value.as_bytes())?)),
            Transform::Noise {
                sensitivity,
                epsilon,
            } => {
                let n: f64 = value.parse().map_err(|_| ShatterError::InvalidParameter)?;
                Some(format!("{:.4}", add_noise(n, *sensitivity, *epsilon)?))
            }
        })
    }

    /// Sizes of each quasi-identifier cohort in `events`.
    fn cohort_sizes(&self, events: &[Event]) -> Vec<usize> {
        let mut cohorts: BTreeMap<Vec<&str>, usize> = BTreeMap::new();
        for event in events {
            let key: Vec<&str> = self
                .quasi_identifiers
                .iter()
                .map(|qi| event.get(qi).unwrap_or(""))
                .collect();
            *cohorts.entry(key).or_default() += 1;
        }
        cohorts.into_values().collect()
    }
}

/// One anonymized record. Contains only fields the policy allowed through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    fields: BTreeMap<String, String>,
}

impl Event {
    /// Builds an event from `(name, value)` pairs. Used by tests in this crate.
    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self {
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    /// The anonymized value of `name`, if it was emitted.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// Number of emitted fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no fields were emitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Destination for anonymized events. The real tpt-strata adapter will implement this.
pub trait EventSink {
    /// Writes a batch. Failure means nothing from the batch should be considered emitted.
    fn emit(&self, batch: &[Event]) -> Result<(), ShatterError>;
}

/// In-memory sink for tests and local runs.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<Event>>,
}

impl MemorySink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies out everything emitted so far.
    pub fn events(&self) -> Result<Vec<Event>, ShatterError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .clone())
    }
}

impl EventSink for MemorySink {
    fn emit(&self, batch: &[Event]) -> Result<(), ShatterError> {
        self.events
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .extend_from_slice(batch);
        Ok(())
    }
}

/// Outcome of a successful [`Emitter::emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitReport {
    /// Events handed to the sink.
    pub emitted: usize,
}

/// Anonymizes records, applies the k-anonymity gate, and emits to a sink.
pub struct Emitter<S: EventSink> {
    policy: Policy,
    sink: S,
}

impl<S: EventSink> Emitter<S> {
    /// Creates an emitter from a policy and a sink.
    #[must_use]
    pub fn new(policy: Policy, sink: S) -> Self {
        Self { policy, sink }
    }

    /// The sink this emitter writes to. Useful for inspecting output in tests.
    #[must_use]
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    /// Anonymizes and emits `records`.
    ///
    /// The batch is refused with [`ShatterError::KAnonymityViolation`] if any
    /// quasi-identifier cohort is smaller than `k`. Nothing is emitted in that case.
    /// Records are consumed, so their values are zeroed on drop.
    pub fn emit(&self, records: Vec<Record>) -> Result<EmitReport, ShatterError> {
        let events = records
            .iter()
            .map(|r| self.policy.transform(r))
            .collect::<Result<Vec<_>, _>>()?;
        drop(records);
        check_k_anonymity(&self.policy.cohort_sizes(&events), self.policy.k)?;
        self.sink.emit(&events)?;
        Ok(EmitReport {
            emitted: events.len(),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_NAME: &str = "A. Example";
    const RAW_CARD: &str = "4111111111111111";

    fn policy(k: usize) -> Policy {
        Policy::new(
            b"test-salt".to_vec(),
            [
                ("name".to_owned(), Transform::Pseudonymize),
                ("birth_year".to_owned(), Transform::Bucket { width: 10 }),
                ("card_number".to_owned(), Transform::Mask { keep_last: 4 }),
                (
                    "balance".to_owned(),
                    Transform::Noise {
                        sensitivity: 1.0,
                        epsilon: 1.0,
                    },
                ),
            ],
            vec!["birth_year".to_owned()],
            k,
        )
        .expect("policy")
    }

    fn person(name: &str, year: &str) -> Record {
        let mut r = Record::new();
        r.insert("name", name);
        r.insert("birth_year", year);
        r.insert("card_number", RAW_CARD);
        r.insert("balance", "100.0");
        r.insert("ssn", "123-45-6789");
        r
    }

    #[test]
    fn output_contains_no_raw_identifiers() {
        let emitter = Emitter::new(policy(1), MemorySink::new());
        emitter.emit(vec![person(RAW_NAME, "1994")]).expect("emit");
        let events = emitter.sink.events().expect("events");
        let debug = format!("{events:?}");
        assert!(!debug.contains(RAW_NAME));
        assert!(!debug.contains("4111111111"));
        assert!(!debug.contains("123-45-6789"));
        assert_eq!(events[0].get("birth_year"), Some("1990-1999"));
        assert_eq!(events[0].get("card_number"), Some("************1111"));
        assert_eq!(events[0].get("ssn"), None);
    }

    #[test]
    fn pseudonyms_are_stable_hex_digests() {
        let p = policy(1);
        let a = p.transform(&person(RAW_NAME, "1990")).expect("a");
        let b = p.transform(&person(RAW_NAME, "1990")).expect("b");
        let name = a.get("name").expect("name");
        assert_eq!(name.len(), 64);
        assert!(name.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a.get("name"), b.get("name"));
    }

    #[test]
    fn noise_stays_numeric() {
        let event = policy(1)
            .transform(&person(RAW_NAME, "1990"))
            .expect("event");
        let noisy: f64 = event
            .get("balance")
            .expect("balance")
            .parse()
            .expect("number");
        assert!(noisy.is_finite());
    }

    #[test]
    fn fields_without_a_rule_are_dropped() {
        let event = policy(1)
            .transform(&person(RAW_NAME, "1990"))
            .expect("event");
        assert_eq!(event.get("ssn"), None);
        assert_eq!(event.len(), 4);
    }

    #[test]
    fn k_gate_refuses_the_whole_batch_when_a_cohort_is_small() {
        let emitter = Emitter::new(policy(3), MemorySink::new());
        let batch = vec![
            person("A", "1990"),
            person("B", "1990"),
            person("C", "1990"),
            person("D", "1980"),
        ];
        assert_eq!(
            emitter.emit(batch).err(),
            Some(ShatterError::KAnonymityViolation)
        );
        assert!(emitter.sink.events().expect("events").is_empty());
    }

    #[test]
    fn k_gate_passes_when_every_cohort_is_large_enough() {
        let emitter = Emitter::new(policy(3), MemorySink::new());
        let batch = vec![
            person("A", "1990"),
            person("B", "1995"),
            person("C", "1999"),
        ];
        let report = emitter.emit(batch).expect("emit");
        assert_eq!(report.emitted, 3);
        assert_eq!(emitter.sink.events().expect("events").len(), 3);
    }

    #[test]
    fn bad_numeric_values_are_rejected() {
        let mut r = person(RAW_NAME, "not-a-year");
        r.insert("balance", "lots");
        assert_eq!(
            policy(1).transform(&r).err(),
            Some(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn policy_validation() {
        let rules = [("a".to_owned(), Transform::Pseudonymize)];
        assert!(Policy::new(vec![], rules.clone(), vec![], 1).is_err());
        assert!(Policy::new(b"s".to_vec(), rules.clone(), vec![], 0).is_err());
        // A quasi-identifier with no rule is rejected.
        assert!(Policy::new(b"s".to_vec(), rules.clone(), vec!["zip".to_owned()], 1).is_err());
        // A quasi-identifier that is dropped is rejected.
        let dropped = [("zip".to_owned(), Transform::Drop)];
        assert!(Policy::new(b"s".to_vec(), dropped, vec!["zip".to_owned()], 1).is_err());
        let bad_width = [("y".to_owned(), Transform::Bucket { width: 0 })];
        assert!(Policy::new(b"s".to_vec(), bad_width, vec![], 1).is_err());
    }
}

/// Durable, append-only sink: one JSON object per line, one line per event.
///
/// The analytics store is rebuilt from this file, so the file is the durable copy.
/// Each batch is flushed with `sync_data` before `emit` returns, so a successful
/// return means the batch is on disk. Only fields the policy allowed through are written.
pub struct JsonlSink {
    file: Mutex<File>,
}

impl JsonlSink {
    /// Opens (or creates) the log for appending.
    pub fn open(path: &Path) -> Result<Self, ShatterError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| ShatterError::Internal)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Reads every event back, in write order. Any malformed line fails the whole read.
    pub fn read_all(path: &Path) -> Result<Vec<Event>, ShatterError> {
        let file = File::open(path).map_err(|_| ShatterError::Internal)?;
        BufReader::new(file)
            .lines()
            .map(|line| {
                let line = line.map_err(|_| ShatterError::Internal)?;
                let map: BTreeMap<String, String> =
                    serde_json::from_str(&line).map_err(|_| ShatterError::Internal)?;
                Ok(Event { fields: map })
            })
            .collect()
    }
}

impl EventSink for JsonlSink {
    fn emit(&self, batch: &[Event]) -> Result<(), ShatterError> {
        let mut out = Vec::new();
        for event in batch {
            serde_json::to_writer(&mut out, &event.fields).map_err(|_| ShatterError::Internal)?;
            out.push(b'\n');
        }
        let mut file = self.file.lock().map_err(|_| ShatterError::Internal)?;
        file.write_all(&out).map_err(|_| ShatterError::Internal)?;
        file.sync_data().map_err(|_| ShatterError::Internal)
    }
}

#[cfg(test)]
mod jsonl_tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-{name}-{nanos}.jsonl"))
    }

    fn event(pairs: &[(&str, &str)]) -> Event {
        Event {
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn events_round_trip_through_the_file_in_order() {
        let path = temp_path("roundtrip");
        let sink = JsonlSink::open(&path).expect("open");
        sink.emit(&[event(&[("age_band", "30-39")])]).expect("emit");
        sink.emit(&[
            event(&[("age_band", "40-49"), ("note", "quote \" and \\ slash")]),
            event(&[("age_band", "50-59")]),
        ])
        .expect("emit");
        let back = JsonlSink::read_all(&path).expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].get("age_band"), Some("30-39"));
        assert_eq!(back[1].get("note"), Some("quote \" and \\ slash"));
        assert_eq!(back[2].get("age_band"), Some("50-59"));
    }

    #[test]
    fn reopening_appends_rather_than_truncates() {
        let path = temp_path("append");
        JsonlSink::open(&path)
            .expect("open")
            .emit(&[event(&[("a", "1")])])
            .expect("emit");
        JsonlSink::open(&path)
            .expect("reopen")
            .emit(&[event(&[("a", "2")])])
            .expect("emit");
        let back = JsonlSink::read_all(&path).expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn malformed_line_fails_the_read() {
        let path = temp_path("malformed");
        std::fs::write(&path, "{\"a\":\"1\"}\nnot json\n").expect("write");
        let result = JsonlSink::read_all(&path);
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(result.err(), Some(ShatterError::Internal));
    }
}
