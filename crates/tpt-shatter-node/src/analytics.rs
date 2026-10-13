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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ExportConfig;
use serde::Deserialize;
use tpt_shatter_common::{Record, ShatterError};
use tpt_shatter_emitter::{
    Emitter, Event, Policy, StrataSink, Transform, count_by_events, read_log, sum_by_events,
    table_rows,
};

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
/// Where scheduled exports go, and what each one contains.
#[derive(Debug, Clone)]
pub struct ExportPlan {
    /// Directory the CSV files are written into.
    pub dir: PathBuf,
    /// The exports to write on each pass.
    pub exports: Vec<ExportConfig>,
}

pub struct Analytics {
    emitter: Emitter<StrataSink>,
    /// Anonymized events not yet emitted, each with the time it was accepted.
    held: Mutex<Vec<(u64, Event)>>,
    retention_secs: u64,
    k: usize,
    log: PathBuf,
    plan: Option<ExportPlan>,
}

impl Analytics {
    /// Opens the strata sink at `log` and pairs it with `policy`.
    /// With `plan`, exports are written by [`Analytics::write_exports`].
    pub fn open(
        policy: Policy,
        log: &Path,
        retention_secs: u64,
        plan: Option<ExportPlan>,
    ) -> Result<Self, ShatterError> {
        if retention_secs == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        if let Some(plan) = &plan {
            for export in &plan.exports {
                // A file name only: no directory parts, so an export cannot leave its directory.
                let plain = Path::new(&export.file).file_name() == Some(export.file.as_ref());
                if !plain || export.file.is_empty() {
                    return Err(ShatterError::InvalidParameter);
                }
            }
        }
        let k = policy.k();
        Ok(Self {
            emitter: Emitter::new(policy, StrataSink::open(log)?),
            held: Mutex::new(Vec::new()),
            retention_secs,
            k,
            log: log.to_path_buf(),
            plan,
        })
    }

    /// Writes each configured export as a CSV in the export directory, replacing the previous
    /// file. Each file is written beside its name and renamed into place, so a reader never
    /// sees a half-written file. Returns how many files were written.
    pub fn write_exports(&self, now: u64) -> Result<usize, ShatterError> {
        let Some(plan) = &self.plan else {
            return Ok(0);
        };
        let cutoff = now.saturating_sub(self.retention_secs);
        for export in &plan.exports {
            let csv = export_csv(
                &self.log,
                self.k,
                cutoff,
                &export.group,
                export.value.as_deref(),
            )?;
            write_atomically(&plan.dir.join(&export.file), &csv)?;
        }
        Ok(plan.exports.len())
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

/// Writes a CSV of `group` with either a count or, when `value` is given, the sum of
/// `value`. Only events stored at or after `cutoff` count. A group with fewer than `k`
/// events is left out, since a small cohort could identify the people in it.
///
/// Reads the log without writing it, so it is safe while the node is running.
pub fn export_csv(
    log: &Path,
    k: usize,
    cutoff: u64,
    group: &str,
    value: Option<&str>,
) -> Result<String, ShatterError> {
    let events: Vec<_> = read_log(log)?
        .into_iter()
        .filter(|(at, _)| *at >= cutoff)
        .collect();
    let counts = table_rows(&count_by_events(&events, group)?)?;
    let allowed: BTreeSet<String> = counts
        .iter()
        .filter_map(|row| {
            let count: usize = row[1].parse().ok()?;
            (count >= k).then(|| row[0].clone())
        })
        .collect();

    let (header, rows) = match value {
        None => (
            vec![group.to_owned(), "count".to_owned()],
            counts
                .into_iter()
                .filter(|row| allowed.contains(&row[0]))
                .collect::<Vec<_>>(),
        ),
        Some(value) => (
            vec![group.to_owned(), format!("sum({value})")],
            table_rows(&sum_by_events(&events, group, value)?)?
                .into_iter()
                .filter(|row| allowed.contains(&row[0]))
                .collect(),
        ),
    };

    let mut rows = rows;
    rows.sort();
    let mut out = String::new();
    out.push_str(&csv_line(&header));
    for row in &rows {
        out.push_str(&csv_line(row));
    }
    Ok(out)
}

/// One CSV line. Fields with separators or quotes are quoted. A field starting with a
/// spreadsheet formula character gets a leading apostrophe, so a spreadsheet shows it as text.
fn csv_line(fields: &[String]) -> String {
    let mut line = fields
        .iter()
        .map(|field| {
            let guarded = if field.starts_with(['=', '+', '-', '@']) {
                format!("'{field}")
            } else {
                field.clone()
            };
            if guarded.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", guarded.replace('"', "\"\""))
            } else {
                guarded
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

/// Writes `text` to a temporary file beside `path`, syncs it, and renames it into place.
fn write_atomically(path: &Path, text: &str) -> Result<(), ShatterError> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    {
        let mut file = fs::File::create(&tmp).map_err(|_| ShatterError::Internal)?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| ShatterError::Internal)?;
    }
    fs::rename(&tmp, path).map_err(|_| ShatterError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tpt_shatter_common::Record;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-analytics-{name}-{nanos}.jsonl"))
    }

    fn policy(k: usize) -> Policy {
        Policy::new(
            b"export-test-salt".to_vec(),
            [
                ("name".to_owned(), Transform::Pseudonymize),
                ("birth_year".to_owned(), Transform::Bucket { width: 10 }),
                (
                    "balance".to_owned(),
                    Transform::Noise {
                        sensitivity: 1e-6,
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
        let mut record = Record::new();
        record.insert("name", name);
        record.insert("birth_year", year);
        record
    }

    /// Four people in two decades, so k=2 passes, each with a distinct name.
    fn filled(log: &Path) -> Analytics {
        let analytics = Analytics::open(policy(2), log, 3600, None).expect("open");
        for (name, year) in [("A", "1994"), ("B", "1995"), ("C", "2004"), ("D", "2005")] {
            let events = analytics.prepare(&person(name, year)).expect("prepare");
            analytics.hold(events, 1_000).expect("hold");
        }
        assert_eq!(analytics.flush(1_000), Ok(4));
        analytics
    }

    #[test]
    fn export_counts_each_decade_and_leaves_out_small_groups() {
        let log = temp_path("counts");
        let _analytics = filled(&log);
        let csv = export_csv(&log, 2, 0, "birth_year", None).expect("export");
        assert_eq!(csv, "birth_year,count\n1990-1999,2\n2000-2009,2\n");

        // Pseudonyms are unique, so every name group has one event and is left out.
        let by_name = export_csv(&log, 2, 0, "name", None).expect("export");
        std::fs::remove_file(&log).expect("cleanup");
        assert_eq!(by_name, "name,count\n");
    }

    #[test]
    fn export_ignores_events_before_the_cutoff() {
        let log = temp_path("cutoff");
        let _analytics = filled(&log);
        let csv = export_csv(&log, 2, 2_000, "birth_year", None).expect("export");
        std::fs::remove_file(&log).expect("cleanup");
        assert_eq!(csv, "birth_year,count\n");
    }

    #[test]
    fn export_sums_a_value_per_group() {
        let log = temp_path("sums");
        let analytics = Analytics::open(policy(2), &log, 3600, None).expect("open");
        for (year, balance) in [("1994", "10"), ("1995", "5"), ("2004", "7"), ("2005", "1")] {
            let mut record = person("A", year);
            record.insert("balance", balance);
            analytics
                .hold(analytics.prepare(&record).expect("prepare"), 1_000)
                .expect("hold");
        }
        assert_eq!(analytics.flush(1_000), Ok(4));
        let csv = export_csv(&log, 2, 0, "birth_year", Some("balance")).expect("export");
        std::fs::remove_file(&log).expect("cleanup");
        // Sums are noisy by design, so compare each one within a small tolerance.
        let sums: Vec<(String, f64)> = csv
            .lines()
            .skip(1)
            .map(|line| {
                let (group, sum) = line.split_once(',').expect("row");
                (group.to_owned(), sum.parse().expect("number"))
            })
            .collect();
        assert_eq!(sums.len(), 2, "{csv}");
        assert_eq!(sums[0].0, "1990-1999");
        assert!((sums[0].1 - 15.0).abs() < 0.001, "{csv}");
        assert_eq!(sums[1].0, "2000-2009");
        assert!((sums[1].1 - 8.0).abs() < 0.001, "{csv}");
    }

    #[test]
    fn csv_guards_formulas_and_quotes_separators() {
        let line = csv_line(&["=HYPERLINK(1)".to_owned(), "a,\"b\"".to_owned()]);
        assert_eq!(line, "'=HYPERLINK(1),\"a,\"\"b\"\"\"\n");
    }
}
