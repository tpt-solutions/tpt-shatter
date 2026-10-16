// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Canary detection on the assembler host.
//!
//! The assembler reads canaries through its own router, which the node never sees. So the
//! assembler watches its own router, using the canary FragmentIds the node pushes to it (or
//! writes to the list file). It holds no canary key.
//!
//! Reads are refused for two reasons, tracked separately in [`ReadGate`]:
//! - **Awaiting a list.** Until the first list arrives, nothing is watched, so no read is
//!   served. The node's first push clears this.
//! - **Alarmed.** The first canary read fires the gate, and the gate stays set until restart.
//!   A new list does not clear it. A restart is the re-arm step, taken after someone has
//!   read the alert log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tpt_shatter_canary::{Alarm, CanaryIds, CanaryMonitor, CanaryWatch, Responder};
use tpt_shatter_common::{AlertLog, Record, ShardKey, ShatterError};
use tpt_shatter_gateway::RecordSource;

/// Why reads are being refused, if they are. Shared between the record source and the watcher.
#[derive(Debug)]
pub struct ReadGate {
    awaiting_list: AtomicBool,
    alarmed: AtomicBool,
}

impl ReadGate {
    /// A gate that starts open, or that waits for a list when `awaiting_list` is set.
    #[must_use]
    pub const fn new(awaiting_list: bool) -> Self {
        Self {
            awaiting_list: AtomicBool::new(awaiting_list),
            alarmed: AtomicBool::new(false),
        }
    }

    /// Whether reads are refused for either reason.
    #[must_use]
    pub fn refuses(&self) -> bool {
        self.awaiting_list.load(Ordering::SeqCst) || self.alarmed.load(Ordering::SeqCst)
    }

    /// Whether the assembler is waiting for its first list.
    #[must_use]
    pub fn is_awaiting_list(&self) -> bool {
        self.awaiting_list.load(Ordering::SeqCst)
    }

    /// Whether a canary read has fired the gate.
    #[must_use]
    pub fn is_alarmed(&self) -> bool {
        self.alarmed.load(Ordering::SeqCst)
    }

    fn list_loaded(&self) {
        self.awaiting_list.store(false, Ordering::SeqCst);
    }

    fn alarm(&self) {
        self.alarmed.store(true, Ordering::SeqCst);
    }
}

/// Refuses reads while the gate refuses, and passes them through otherwise.
pub struct LockedSource {
    inner: Arc<dyn RecordSource>,
    gate: Arc<ReadGate>,
}

impl LockedSource {
    /// Wraps `inner`. The gate is shared with the [`CanaryWatcher`] that updates it.
    #[must_use]
    pub fn new(inner: Arc<dyn RecordSource>, gate: Arc<ReadGate>) -> Self {
        Self { inner, gate }
    }
}

impl RecordSource for LockedSource {
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        if self.gate.refuses() {
            return Err(ShatterError::ServiceUnavailable);
        }
        self.inner.fetch(shard)
    }
}

/// The gate's responder. The alarm gate is the response, so there is no key to rotate and no
/// notification to send here. The monitor writes each alarm to the alert log.
struct LockResponder;

impl Responder for LockResponder {
    fn rotate_signing_key(&self) -> Result<(), ShatterError> {
        Ok(())
    }

    fn notify_security(&self, _alarm: &Alarm) -> Result<(), ShatterError> {
        Ok(())
    }
}

/// How old the held canary list may get before it counts as stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// The node's rotation period. Must match the node's `canary_period_secs`.
    pub period_secs: u64,
    /// Seconds past the end of the held epoch before the list is stale. This covers the gap
    /// until the node's next pass after a boundary.
    pub grace_secs: u64,
}

/// Reloads the canary list on each pass, and runs the alarm gate over the accesses it saw.
pub struct CanaryWatcher {
    list: PathBuf,
    watch: Arc<CanaryWatch>,
    monitor: CanaryMonitor,
    alerts: AlertLog,
    /// The epoch of the list being watched, or `None` while awaiting the first list.
    epoch: Option<u64>,
    gate: Arc<ReadGate>,
    freshness: Freshness,
    /// Whether the stale alert has been written for the current stale stretch.
    stale_reported: bool,
}

impl CanaryWatcher {
    /// Creates a watcher. `ids` is the list `watch` was built from, or `None` while awaiting the
    /// first list, in which case `watch` must be empty. Alarms, rejected lists, and stale lists
    /// are appended to the log at `alert_path`.
    pub fn new(
        list: PathBuf,
        ids: Option<&CanaryIds>,
        watch: Arc<CanaryWatch>,
        alert_path: &Path,
        gate: Arc<ReadGate>,
        freshness: Freshness,
    ) -> Result<Self, ShatterError> {
        if freshness.period_secs == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        // The cooldown is zero because re-arming happens only on restart; see the module docs.
        let monitor = CanaryMonitor::new(Arc::clone(&watch), 0, AlertLog::open(alert_path)?);
        Ok(Self {
            list,
            watch,
            monitor,
            alerts: AlertLog::open(alert_path)?,
            epoch: ids.map(CanaryIds::epoch),
            gate,
            freshness,
            stale_reported: false,
        })
    }

    /// One pass at time `now` (Unix seconds): reload the list, check it is fresh, then run the
    /// gate over what the watch has seen. A list that cannot be read, or that is older than the
    /// one held, is refused and logged, and the held canaries stay in force. A held list that
    /// has gone stale is logged once per stale stretch. Serving continues, because the alarm
    /// gate is reserved for a canary read.
    pub fn pass(&mut self, now: u64) -> Result<(), ShatterError> {
        // Failed alert writes must not skip the gate, so their errors are kept and returned last.
        let reloaded = self.reload();
        let rejection = match reloaded {
            Err(_) => self.alerts.append(
                "canary_list_rejected",
                now,
                &[("reason", "unreadable or out of order")],
            ),
            Ok(()) => Ok(()),
        };
        let freshness = self.check_freshness(now);
        let was_armed = self.monitor.is_armed();
        let polled = self.monitor.poll(&LockResponder, now);
        // Set the alarm from the gate's state, not from the poll's result. The gate can fire
        // even when the alert write that follows it fails.
        if was_armed && !self.monitor.is_armed() {
            self.gate.alarm();
        }
        polled?;
        rejection?;
        freshness?;
        reloaded
    }

    fn check_freshness(&mut self, now: u64) -> Result<(), ShatterError> {
        // Nothing to check while awaiting: there is no epoch yet.
        let Some(epoch) = self.epoch else {
            return Ok(());
        };
        let epoch_end = epoch
            .checked_add(1)
            .and_then(|next| next.checked_mul(self.freshness.period_secs))
            .ok_or(ShatterError::InvalidParameter)?;
        let stale = now > epoch_end.saturating_add(self.freshness.grace_secs);
        if stale && !self.stale_reported {
            let epoch = epoch.to_string();
            self.alerts
                .append("canary_list_stale", now, &[("epoch", &epoch)])?;
        }
        self.stale_reported = stale;
        Ok(())
    }

    fn reload(&mut self) -> Result<(), ShatterError> {
        // While awaiting, a missing file just means the node has not pushed yet. That is not
        // a rejection, so it is not logged.
        if self.epoch.is_none() && !self.list.exists() {
            return Ok(());
        }
        let ids = CanaryIds::read_file(&self.list)?;
        if self.epoch.is_some_and(|held| ids.epoch() < held) {
            return Err(ShatterError::InvalidParameter);
        }
        if self.epoch != Some(ids.epoch()) {
            self.watch.replace_ids(&ids)?;
            self.epoch = Some(ids.epoch());
        }
        self.gate.list_loaded();
        Ok(())
    }
}
