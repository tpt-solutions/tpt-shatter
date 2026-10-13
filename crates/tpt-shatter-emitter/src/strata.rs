// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Analytics adapter for tpt-strata.
//!
//! Strata is an in-memory engine with no persistence (see `UPSTREAM.md`). So every
//! event goes to the durable [`JsonlSink`] first, and this sink also keeps it in
//! memory. Strata tables are built from memory on demand. On [`StrataSink::open`] the
//! events are read back from the log, so a restart rebuilds the analytics view.
//!
//! Only grouped aggregates are exposed, never whole tables. So the adapter cannot hand
//! out more than an aggregate.

use std::path::Path;
use std::sync::Mutex;

use tpt_shatter_common::ShatterError;
use tpt_strata::{AggFunc, Column, QueryBuilder, Scalar, Table};

use crate::{Event, EventSink, JsonlSink};

/// Event sink that keeps a durable log and an in-memory strata view.
pub struct StrataSink {
    durable: JsonlSink,
    events: Mutex<Vec<Event>>,
}

impl StrataSink {
    /// Opens the log at `path`, loading any events it already holds.
    pub fn open(path: &Path) -> Result<Self, ShatterError> {
        let events = if path.exists() {
            JsonlSink::read_all(path)?
        } else {
            Vec::new()
        };
        Ok(Self {
            durable: JsonlSink::open(path)?,
            events: Mutex::new(events),
        })
    }

    /// Number of events in the view.
    pub fn len(&self) -> Result<usize, ShatterError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .len())
    }

    /// Whether the view holds no events.
    pub fn is_empty(&self) -> Result<bool, ShatterError> {
        Ok(self.len()? == 0)
    }

    /// Row count for each distinct value of `group`, as a strata table with a
    /// `group` column and a count column. Missing values group as NULL.
    pub fn count_by(&self, group: &str) -> Result<Table, ShatterError> {
        let table = {
            let events = self.events.lock().map_err(|_| ShatterError::Internal)?;
            Table::try_new(vec![string_column(&events, group)])
                .map_err(|_| ShatterError::Internal)?
        };
        aggregate(&table, group, group, AggFunc::Count)
    }

    /// Sum of the numeric `value` field for each distinct `group` value.
    ///
    /// Every present value of `value` must parse as a number. Otherwise this returns
    /// [`ShatterError::InvalidParameter`], since summing a non-numeric field would give
    /// a misleading total.
    pub fn sum_by(&self, group: &str, value: &str) -> Result<Table, ShatterError> {
        let table = {
            let events = self.events.lock().map_err(|_| ShatterError::Internal)?;
            let columns = vec![
                string_column(&events, group),
                number_column(&events, value)?,
            ];
            Table::try_new(columns).map_err(|_| ShatterError::Internal)?
        };
        aggregate(&table, group, value, AggFunc::Sum)
    }
}

impl EventSink for StrataSink {
    fn emit(&self, batch: &[Event]) -> Result<(), ShatterError> {
        // Durable first. If the log write fails, nothing is added to the view.
        self.durable.emit(batch)?;
        self.events
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .extend_from_slice(batch);
        Ok(())
    }
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
fn string_column(events: &[Event], field: &str) -> Column {
    let values = events
        .iter()
        .map(|e| match e.get(field) {
            Some(v) => Scalar::Str(v.to_owned()),
            None => Scalar::Null,
        })
        .collect();
    Column::new(field, values)
}

/// A numeric column of `field` values. Fails if a present value is not a number.
fn number_column(events: &[Event], field: &str) -> Result<Column, ShatterError> {
    let mut values = Vec::with_capacity(events.len());
    for event in events {
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
}
