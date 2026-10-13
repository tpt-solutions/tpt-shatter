// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Security alert log: an append-only JSON-lines file that a pager or SIEM tails.
//!
//! This is the notification channel the alarm responders write to. A line holds a
//! kind, a timestamp, and a small set of `key=value` pairs chosen by the caller. The
//! caller must pass only identifiers that are safe to log, such as a vault label or a
//! canary index. Never pass canary values, FragmentIds, tokens, or field values.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{Map, Value, json};

use crate::error::ShatterError;

/// Keys that would carry sensitive values. Rejected even if a caller passes them.
const FORBIDDEN_KEYS: &[&str] = &[
    "token",
    "fragment_id",
    "fragment",
    "value",
    "field",
    "record",
];

/// Append-only alert file, synced after every line.
pub struct AlertLog {
    file: Mutex<File>,
}

impl AlertLog {
    /// Opens (or creates) the alert log for appending.
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

    /// Appends one alert with the given `kind`, timestamp (Unix seconds), and fields.
    ///
    /// Returns [`ShatterError::InvalidParameter`] if a field key is forbidden, and
    /// writes nothing in that case.
    pub fn append(&self, kind: &str, at: u64, fields: &[(&str, &str)]) -> Result<(), ShatterError> {
        let mut map = Map::new();
        for (key, value) in fields {
            if FORBIDDEN_KEYS.contains(key) {
                return Err(ShatterError::InvalidParameter);
            }
            map.insert((*key).to_owned(), Value::String((*value).to_owned()));
        }
        let line = json!({ "kind": kind, "at": at, "fields": map });
        let mut bytes = serde_json::to_vec(&line).map_err(|_| ShatterError::Internal)?;
        bytes.push(b'\n');
        let mut file = self.file.lock().map_err(|_| ShatterError::Internal)?;
        file.write_all(&bytes).map_err(|_| ShatterError::Internal)?;
        file.sync_data().map_err(|_| ShatterError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-alert-{name}-{nanos}.jsonl"))
    }

    #[test]
    fn appends_one_line_per_alert() {
        let path = temp_path("lines");
        let log = AlertLog::open(&path).expect("open");
        log.append("canary_alarm", 100, &[("vault", "B"), ("index", "3")])
            .expect("append");
        log.append("reap_abandoned", 101, &[("count", "2")])
            .expect("append");
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(r#""kind":"canary_alarm""#));
        assert!(lines[0].contains(r#""vault":"B""#));
        assert!(lines[1].contains(r#""count":"2""#));
    }

    #[test]
    fn forbidden_keys_are_refused_and_nothing_is_written() {
        let path = temp_path("forbidden");
        let log = AlertLog::open(&path).expect("open");
        let result = log.append("canary_alarm", 1, &[("fragment_id", "00ff")]);
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(result, Err(ShatterError::InvalidParameter));
        assert!(text.is_empty());
    }
}
