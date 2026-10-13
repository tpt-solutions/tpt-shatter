// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Analytics adapter for tpt-strata.
//!
//! Strata is an in-memory engine with no persistence (see `UPSTREAM.md`). So every
//! event goes to a durable log first, and this sink also keeps it in memory. Strata
//! tables are built from memory on demand. On [`StrataSink::open`] the events are read
//! back from the log, so a restart rebuilds the analytics view.
//!
//! Each log line is `{"at": <unix seconds>, "fields": {...}}`. The time lets
//! [`StrataSink::purge_before`] enforce a retention window on both the log and the view.
//!
//! Only grouped aggregates are exposed, never whole tables. So the adapter cannot hand
//! out more than an aggregate.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_shatter_common::ShatterError;
use tpt_strata::{AggFunc, Column, DataType, Field, QueryBuilder, Scalar, Schema, Table};

use crate::{Event, EventSink};

/// One stored event and the time it was stored (Unix seconds).
pub type Stamped = (u64, Event);

/// Event sink that keeps a durable log and an in-memory strata view.
pub struct StrataSink {
    path: PathBuf,
    state: Mutex<State>,
}

struct State {
    /// `None` only while a purge swaps the log. A purge that fails leaves it `None`, so
    /// later appends fail rather than write through a stale handle.
    file: Option<File>,
    events: Vec<Stamped>,
}

impl StrataSink {
    /// Opens the log at `path`, loading any events it already holds.
    ///
    /// A log written before timestamps were added fails to load. Nothing in this workspace
    /// has such a log in production.
    pub fn open(path: &Path) -> Result<Self, ShatterError> {
        let events = read_log(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(State {
                file: Some(open_append(path)?),
                events,
            }),
        })
    }

    /// Number of events in the view.
    pub fn len(&self) -> Result<usize, ShatterError> {
        Ok(self.lock()?.events.len())
    }

    /// Whether the view holds no events.
    pub fn is_empty(&self) -> Result<bool, ShatterError> {
        Ok(self.len()? == 0)
    }

    /// Stores each event with its own time. Durable first: the log is synced before the
    /// view changes, so a failed write leaves the view as it was.
    pub fn append(&self, items: &[Stamped]) -> Result<(), ShatterError> {
        let mut state = self.lock()?;
        let file = state.file.as_mut().ok_or(ShatterError::Internal)?;
        let mut out = String::new();
        for (at, event) in items {
            out.push_str(&encode(*at, event)?);
            out.push('\n');
        }
        file.write_all(out.as_bytes())
            .and_then(|()| file.sync_data())
            .map_err(|_| ShatterError::Internal)?;
        state.events.extend(items.iter().cloned());
        Ok(())
    }

    /// Removes every event stored before `cutoff` (Unix seconds), from the log and the view.
    /// Returns how many were removed. The log is rewritten through a temporary file and
    /// renamed into place, so a crash leaves either the old log or the new one.
    pub fn purge_before(&self, cutoff: u64) -> Result<usize, ShatterError> {
        let mut state = self.lock()?;
        let removed = state.events.iter().filter(|(at, _)| *at < cutoff).count();
        if removed == 0 {
            return Ok(0);
        }
        let kept: Vec<Stamped> = state
            .events
            .iter()
            .filter(|(at, _)| *at >= cutoff)
            .cloned()
            .collect();
        // Release the handle first: Windows will not rename over an open file.
        state.file = None;
        write_log(&self.path, &kept)?;
        state.file = Some(open_append(&self.path)?);
        state.events = kept;
        Ok(removed)
    }

    /// Row count for each distinct value of `group`, as a strata table with a
    /// `group` column and a count column. Missing values group as NULL.
    ///
    /// An empty view gives an empty table. A `group` that no event holds is refused.
    pub fn count_by(&self, group: &str) -> Result<Table, ShatterError> {
        let table = {
            let state = self.lock()?;
            if state.events.is_empty() {
                return Ok(empty_grouped(group, group, AggFunc::Count, DataType::Int64));
            }
            require_field(&state.events, group)?;
            Table::try_new(vec![string_column(&state.events, group)])
                .map_err(|_| ShatterError::Internal)?
        };
        aggregate(&table, group, group, AggFunc::Count)
    }

    /// Sum of the numeric `value` field for each distinct `group` value.
    ///
    /// Every present value of `value` must parse as a number. Otherwise this returns
    /// [`ShatterError::InvalidParameter`], since summing a non-numeric field would give
    /// a misleading total. An empty view gives an empty table. A field that no event holds
    /// is refused.
    pub fn sum_by(&self, group: &str, value: &str) -> Result<Table, ShatterError> {
        let table = {
            let state = self.lock()?;
            if state.events.is_empty() {
                return Ok(empty_grouped(group, value, AggFunc::Sum, DataType::Float64));
            }
            require_field(&state.events, group)?;
            require_field(&state.events, value)?;
            let columns = vec![
                string_column(&state.events, group),
                number_column(&state.events, value)?,
            ];
            Table::try_new(columns).map_err(|_| ShatterError::Internal)?
        };
        aggregate(&table, group, value, AggFunc::Sum)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, ShatterError> {
        self.state.lock().map_err(|_| ShatterError::Internal)
    }
}

impl EventSink for StrataSink {
    fn emit(&self, batch: &[Event]) -> Result<(), ShatterError> {
        let at = now_secs();
        let items: Vec<Stamped> = batch.iter().map(|e| (at, e.clone())).collect();
        self.append(&items)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn open_append(path: &Path) -> Result<File, ShatterError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| ShatterError::Internal)
}

/// Writes `items` to a temporary file beside `path`, syncs it, and renames it into place.
fn write_log(path: &Path, items: &[Stamped]) -> Result<(), ShatterError> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    {
        let mut file = File::create(&tmp).map_err(|_| ShatterError::Internal)?;
        for (at, event) in items {
            let mut line = encode(*at, event)?;
            line.push('\n');
            file.write_all(line.as_bytes())
                .map_err(|_| ShatterError::Internal)?;
        }
        file.sync_all().map_err(|_| ShatterError::Internal)?;
    }
    fs::rename(&tmp, path).map_err(|_| ShatterError::Internal)
}

fn encode(at: u64, event: &Event) -> Result<String, ShatterError> {
    serde_json::to_string(&serde_json::json!({ "at": at, "fields": event.fields }))
        .map_err(|_| ShatterError::Internal)
}

fn decode(line: &str) -> Result<Stamped, ShatterError> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|_| ShatterError::Internal)?;
    let at = value["at"].as_u64().ok_or(ShatterError::Internal)?;
    let fields: BTreeMap<String, String> =
        serde_json::from_value(value["fields"].clone()).map_err(|_| ShatterError::Internal)?;
    Ok((at, Event { fields }))
}

/// Fails if no event holds `field`. Strata cannot infer a type for an all-NULL column,
/// and a field no event has is a wrong name, so it is refused rather than grouped as NULL.
fn require_field(events: &[Stamped], field: &str) -> Result<(), ShatterError> {
    if events.iter().any(|(_, e)| e.get(field).is_some()) {
        Ok(())
    } else {
        Err(ShatterError::InvalidParameter)
    }
}

/// An empty grouped result with the same columns a non-empty one would have.
fn empty_grouped(group: &str, value: &str, func: AggFunc, out: DataType) -> Table {
    let schema = Schema::new(vec![
        Field::new(group, DataType::Utf8, true),
        Field::new(format!("{func}({value})"), out, false),
    ]);
    Table::empty(Arc::new(schema))
}

fn aggregate(
    table: &Table,
    group: &str,
    value: &str,
    func: AggFunc,
) -> Result<Table, ShatterError> {
    QueryBuilder::new(table)
        .group_by(vec![group])
        .and_then(|q| q.aggregate(value, func))
        .and_then(|q| q.execute())
        .map_err(|_| ShatterError::Internal)
}

/// A string column of `field` values, with NULL for events that lack the field.
fn string_column(events: &[Stamped], field: &str) -> Column {
    let values = events
        .iter()
        .map(|(_, e)| match e.get(field) {
            Some(v) => Scalar::Str(v.to_owned()),
            None => Scalar::Null,
        })
        .collect();
    Column::new(field, values)
}

/// A numeric column of `field` values. Fails if a present value is not a number.
fn number_column(events: &[Stamped], field: &str) -> Result<Column, ShatterError> {
    let mut values = Vec::with_capacity(events.len());
    for (_, event) in events {
        match event.get(field) {
            Some(v) => {
                let n: f64 = v.parse().map_err(|_| ShatterError::InvalidParameter)?;
                values.push(Scalar::F64(n));
            }
            None => values.push(Scalar::Null),
        }
    }
    Ok(Column::new(field, values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-strata-{name}-{nanos}.jsonl"))
    }

    /// Reads a grouped table into a map from group value to aggregate value.
    fn rows(table: &Table) -> BTreeMap<String, Scalar> {
        let mut out = BTreeMap::new();
        for batch in table.batches() {
            for row in 0..batch.row_count() {
                let key = match batch.columns[0].get(row) {
                    Some(Scalar::Str(s)) => s,
                    _ => "NULL".to_owned(),
                };
                let value = batch.columns[1].get(row).unwrap_or(Scalar::Null);
                out.insert(key, value);
            }
        }
        out
    }

    #[test]
    fn counts_rows_per_group() {
        let path = temp_path("count");
        let sink = StrataSink::open(&path).expect("open");
        sink.emit(&[
            Event::from_pairs(&[("band", "30-39")]),
            Event::from_pairs(&[("band", "30-39")]),
        ])
        .expect("emit");
        sink.emit(&[Event::from_pairs(&[("band", "40-49")])])
            .expect("emit");
        let counts = sink.count_by("band").expect("count");
        std::fs::remove_file(&path).expect("cleanup");
        let got = rows(&counts);
        assert_eq!(got.get("30-39"), Some(&Scalar::I64(2)));
        assert_eq!(got.get("40-49"), Some(&Scalar::I64(1)));
    }

    #[test]
    fn sums_a_numeric_field_per_group() {
        let path = temp_path("sum");
        let sink = StrataSink::open(&path).expect("open");
        sink.emit(&[
            Event::from_pairs(&[("region", "north"), ("amount", "10.5")]),
            Event::from_pairs(&[("region", "north"), ("amount", "4.5")]),
            Event::from_pairs(&[("region", "south"), ("amount", "3")]),
        ])
        .expect("emit");
        let sums = sink.sum_by("region", "amount").expect("sum");
        std::fs::remove_file(&path).expect("cleanup");
        let got = rows(&sums);
        assert_eq!(got.get("north"), Some(&Scalar::F64(15.0)));
        assert_eq!(got.get("south"), Some(&Scalar::F64(3.0)));
    }

    #[test]
    fn summing_a_non_numeric_field_is_refused() {
        let path = temp_path("nonnumeric");
        let sink = StrataSink::open(&path).expect("open");
        sink.emit(&[Event::from_pairs(&[
            ("region", "north"),
            ("amount", "a lot"),
        ])])
        .expect("emit");
        let result = sink.sum_by("region", "amount").err();
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(result, Some(ShatterError::InvalidParameter));
    }

    #[test]
    fn grouping_an_empty_view_gives_an_empty_table() {
        let path = temp_path("empty");
        let sink = StrataSink::open(&path).expect("open");
        let counts = sink.count_by("band");
        let sums = sink.sum_by("region", "amount");
        std::fs::remove_file(&path).expect("cleanup");
        let counts = counts.expect("count on empty view");
        let sums = sums.expect("sum on empty view");
        assert_eq!(counts.row_count(), 0);
        assert_eq!(sums.row_count(), 0);
        assert_eq!(counts.column_names(), vec!["band", "COUNT(band)"]);
        assert_eq!(sums.column_names(), vec!["region", "SUM(amount)"]);
    }

    #[test]
    fn a_field_no_event_holds_is_refused() {
        let path = temp_path("unknown");
        let sink = StrataSink::open(&path).expect("open");
        sink.emit(&[Event::from_pairs(&[("region", "north")])])
            .expect("emit");
        let counts = sink.count_by("band").err();
        let sums = sink.sum_by("region", "amount").err();
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(counts, Some(ShatterError::InvalidParameter));
        assert_eq!(sums, Some(ShatterError::InvalidParameter));
    }

    #[test]
    fn the_log_and_the_strata_views_hold_no_raw_identifiers() {
        use crate::{Emitter, Policy, Transform};
        use tpt_shatter_common::Record;

        const RAW_NAME: &str = "A. Example";
        const RAW_CARD: &str = "4111111111111111";
        const RAW_SSN: &str = "123-45-6789";

        let path = temp_path("pii");
        let policy = Policy::new(
            b"strata-test-salt".to_vec(),
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
            1,
        )
        .expect("policy");
        let emitter = Emitter::new(policy, StrataSink::open(&path).expect("open"));

        let mut record = Record::new();
        record.insert("name", RAW_NAME);
        record.insert("birth_year", "1994");
        record.insert("card_number", RAW_CARD);
        record.insert("balance", "100.0");
        record.insert("ssn", RAW_SSN);
        emitter.emit(vec![record]).expect("emit");

        let counts = emitter.sink.count_by("birth_year").expect("count");
        let sums = emitter.sink.sum_by("birth_year", "balance").expect("sum");
        let log = std::fs::read_to_string(&path).expect("log");
        std::fs::remove_file(&path).expect("cleanup");

        let views = format!("{counts:?}{sums:?}");
        for text in [&log, &views] {
            assert!(!text.contains(RAW_NAME), "name leaked: {text}");
            assert!(!text.contains("4111111111"), "card leaked: {text}");
            assert!(!text.contains(RAW_SSN), "ssn leaked: {text}");
        }
        assert!(log.contains("1990-1999"), "bucket missing: {log}");
        assert!(views.contains("1990-1999"), "bucket missing in view");
    }

    #[test]
    fn a_restart_rebuilds_the_view_from_the_log() {
        let path = temp_path("restart");
        {
            let sink = StrataSink::open(&path).expect("open");
            sink.emit(&[
                Event::from_pairs(&[("band", "30-39")]),
                Event::from_pairs(&[("band", "30-39")]),
            ])
            .expect("emit");
        }
        let reopened = StrataSink::open(&path).expect("reopen");
        assert_eq!(reopened.len(), Ok(2));
        let counts = reopened.count_by("band").expect("count");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(rows(&counts).get("30-39"), Some(&Scalar::I64(2)));
    }

    #[test]
    fn purge_removes_only_events_before_the_cutoff_from_view_and_log() {
        let path = temp_path("purge");
        {
            let sink = StrataSink::open(&path).expect("open");
            sink.append(&[
                (100, Event::from_pairs(&[("band", "old")])),
                (200, Event::from_pairs(&[("band", "new")])),
            ])
            .expect("append");
            assert_eq!(sink.purge_before(150), Ok(1));
            assert_eq!(sink.len(), Ok(1));
            assert_eq!(sink.purge_before(150), Ok(0), "nothing left to purge");
        }
        let reopened = StrataSink::open(&path).expect("reopen");
        let counts = reopened.count_by("band").expect("count");
        std::fs::remove_file(&path).expect("cleanup");
        let got = rows(&counts);
        assert_eq!(got.len(), 1);
        assert_eq!(got.get("new"), Some(&Scalar::I64(1)));
    }
}
