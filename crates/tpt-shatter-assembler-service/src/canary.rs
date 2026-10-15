// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Canary detection on the assembler host.
//!
//! The assembler reads canaries through its own router, which the node never sees. So the
//! assembler watches its own router, using the canary FragmentIds the node writes to a list
//! file. It holds no canary key. On the first canary read, the gate fires and sets a lock,
//! and a locked assembler refuses every read. The gateway behind it then refuses too.
//!
//! The lock clears only on restart. A restart is the re-arm step, taken after someone has
//! read the alert log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tpt_shatter_canary::{Alarm, CanaryIds, CanaryMonitor, CanaryWatch, Responder};
use tpt_shatter_common::{AlertLog, Record, ShardKey, ShatterError};
use tpt_shatter_gateway::RecordSource;

/// Refuses every read while the lock is set, and passes reads through otherwise.
pub struct LockedSource {
    inner: Arc<dyn RecordSource>,
    locked: Arc<AtomicBool>,
}

impl LockedSource {
    /// Wraps `inner`. The lock is shared with the [`CanaryWatcher`] that sets it.
    #[must_use]
    pub fn new(inner: Arc<dyn RecordSource>, locked: Arc<AtomicBool>) -> Self {
        Self { inner, locked }
    }
}

impl RecordSource for LockedSource {
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(ShatterError::ServiceUnavailable);
        }
        self.inner.fetch(shard)
    }
}

/// The gate's responder. The lock is the response, so there is no key to rotate and no
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
    epoch: u64,
    locked: Arc<AtomicBool>,
    freshness: Freshness,
    /// Whether the stale alert has been written for the current stale stretch.
    stale_reported: bool,
}

impl CanaryWatcher {
    /// Creates a watcher. `ids` must be the list `watch` was built from. Alarms, rejected
    /// lists, and stale lists are appended to the log at `alert_path`.
    pub fn new(
        list: PathBuf,
        ids: &CanaryIds,
        watch: Arc<CanaryWatch>,
        alert_path: &Path,
        locked: Arc<AtomicBool>,
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
            epoch: ids.epoch(),
            locked,
            freshness,
            stale_reported: false,
        })
    }

    /// One pass at time `now` (Unix seconds): reload the list, check it is fresh, then run the
    /// gate over what the watch has seen. A list that cannot be read, or that is older than the
    /// one held, is refused and logged, and the held canaries stay in force. A held list that
    /// has gone stale is logged once per stale stretch. Serving continues, because the lock is
    /// reserved for a canary read.
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
        // Set the lock from the gate's state, not from the poll's result. The gate can fire
        // even when the alert write that follows it fails.
        if was_armed && !self.monitor.is_armed() {
            self.locked.store(true, Ordering::SeqCst);
        }
        polled?;
        rejection?;
        freshness?;
        reloaded
    }

    fn check_freshness(&mut self, now: u64) -> Result<(), ShatterError> {
        let epoch_end = self
            .epoch
            .checked_add(1)
            .and_then(|next| next.checked_mul(self.freshness.period_secs))
            .ok_or(ShatterError::InvalidParameter)?;
        let stale = now > epoch_end.saturating_add(self.freshness.grace_secs);
        if stale && !self.stale_reported {
            let epoch = self.epoch.to_string();
            self.alerts
                .append("canary_list_stale", now, &[("epoch", &epoch)])?;
        }
        self.stale_reported = stale;
        Ok(())
    }

    fn reload(&mut self) -> Result<(), ShatterError> {
        let ids = CanaryIds::read_file(&self.list)?;
        if ids.epoch() < self.epoch {
            return Err(ShatterError::InvalidParameter);
        }
        if ids.epoch() != self.epoch {
            self.watch.replace_ids(&ids)?;
            self.epoch = ids.epoch();
        }
        Ok(())
    }
}
