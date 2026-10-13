// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Connects canary detections to the response: drains the watch, runs the alarm gate,
//! and records every alarm in the security alert log.

use std::sync::Arc;

use tpt_shatter_common::{AlertLog, ShatterError};

use crate::{AlarmGate, CanaryWatch, Outcome, Responder};

/// Polls a [`CanaryWatch`] and runs the response through an [`AlarmGate`].
pub struct CanaryMonitor {
    watch: Arc<CanaryWatch>,
    gate: AlarmGate,
    alerts: AlertLog,
}

impl CanaryMonitor {
    /// Creates a monitor. `cooldown_secs` is the minimum time before the gate can re-arm.
    #[must_use]
    pub fn new(watch: Arc<CanaryWatch>, cooldown_secs: u64, alerts: AlertLog) -> Self {
        Self {
            watch,
            gate: AlarmGate::new(cooldown_secs),
            alerts,
        }
    }

    /// Whether the gate will respond to the next alarm.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.gate.is_armed()
    }

    /// Handles everything queued since the last poll, at time `now` (Unix seconds).
    ///
    /// The response runs first, so security action never waits on a log write. If the
    /// response fails, the alarms go back in the queue and the gate stays armed, so the
    /// next poll retries. After a successful response, each alarm is written to the alert
    /// log. A log failure is returned, but the response has already run.
    pub fn poll(&mut self, responder: &dyn Responder, now: u64) -> Result<Outcome, ShatterError> {
        let alarms = self.watch.take_alarms()?;
        if alarms.is_empty() {
            return Ok(Outcome::Quiet);
        }
        let outcome = match self.gate.handle(&alarms, now, responder) {
            Ok(outcome) => outcome,
            Err(e) => {
                self.watch.requeue(alarms)?;
                return Err(e);
            }
        };
        for alarm in &alarms {
            alarm.record(&self.alerts, now)?;
        }
        Ok(outcome)
    }

    /// Re-arms the gate, once the cooldown has passed. Refused before then.
    pub fn rearm(&mut self, now: u64) -> Result<(), ShatterError> {
        self.gate.rearm(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Alarm, CanaryRotation};
    use std::cell::Cell;
    use tpt_shatter_common::{FragmentId, VaultId};
    use tpt_shatter_vault_client::{Access, AccessObserver, derive_fragment_id};

    const MASTER: [u8; 32] = [0x81; 32];
    const DERIVATION: [u8; 32] = [0x82; 32];
    const WEEK: u64 = 7 * 24 * 3600;
    const NOW: u64 = 30 * WEEK;

    struct CountingResponder {
        rotations: Cell<u32>,
        notifications: Cell<u32>,
        fail_rotation: Cell<bool>,
    }

    impl CountingResponder {
        fn new() -> Self {
            Self {
                rotations: Cell::new(0),
                notifications: Cell::new(0),
                fail_rotation: Cell::new(false),
            }
        }
    }

    impl Responder for CountingResponder {
        fn rotate_signing_key(&self) -> Result<(), ShatterError> {
            if self.fail_rotation.get() {
                return Err(ShatterError::Internal);
            }
            self.rotations.set(self.rotations.get() + 1);
            Ok(())
        }
        fn notify_security(&self, _: &Alarm) -> Result<(), ShatterError> {
            self.notifications.set(self.notifications.get() + 1);
            Ok(())
        }
    }

    fn temp_log(name: &str) -> (std::path::PathBuf, AlertLog) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("tpt-shatter-monitor-{name}-{nanos}.jsonl"));
        let log = AlertLog::open(&path).expect("open");
        (path, log)
    }

    /// A watch for the current epoch, with one canary touched by a direct observer call.
    fn touched_watch() -> Arc<CanaryWatch> {
        let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let plan = rotation.plan_at(NOW).expect("plan");
        let watch = Arc::new(CanaryWatch::new(&plan).expect("watch"));
        let shard = plan.shard(1).expect("shard");
        let id: FragmentId = derive_fragment_id(&DERIVATION, &shard, VaultId::C).expect("id");
        watch.on_access(VaultId::C, &id, Access::Read);
        watch
    }

    #[test]
    fn a_detection_runs_the_response_once_and_is_logged() {
        let (path, log) = temp_log("once");
        let watch = touched_watch();
        let mut monitor = CanaryMonitor::new(Arc::clone(&watch), WEEK, log);
        let responder = CountingResponder::new();

        assert_eq!(
            monitor.poll(&responder, NOW),
            Ok(Outcome::Fired { alarms: 1 })
        );
        assert_eq!(responder.rotations.get(), 1);
        assert_eq!(responder.notifications.get(), 1);
        assert!(!monitor.is_armed());

        // Nothing queued: quiet, and the response is not repeated.
        assert_eq!(monitor.poll(&responder, NOW + 1), Ok(Outcome::Quiet));
        assert_eq!(responder.rotations.get(), 1);

        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        assert!(text.contains(r#""kind":"canary_alarm""#));
        assert!(text.contains(r#""vault":"C""#));
    }

    #[test]
    fn a_failed_response_keeps_the_alarm_for_the_next_poll() {
        let (path, log) = temp_log("retry");
        let watch = touched_watch();
        let mut monitor = CanaryMonitor::new(Arc::clone(&watch), WEEK, log);
        let responder = CountingResponder::new();

        responder.fail_rotation.set(true);
        assert_eq!(monitor.poll(&responder, NOW), Err(ShatterError::Internal));
        assert!(
            monitor.is_armed(),
            "a failed response must leave the gate armed"
        );

        responder.fail_rotation.set(false);
        assert_eq!(
            monitor.poll(&responder, NOW + 1),
            Ok(Outcome::Fired { alarms: 1 })
        );
        std::fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn rearm_waits_for_the_cooldown() {
        let (path, log) = temp_log("rearm");
        let watch = touched_watch();
        let mut monitor = CanaryMonitor::new(watch, WEEK, log);
        monitor.poll(&CountingResponder::new(), NOW).expect("poll");
        assert_eq!(monitor.rearm(NOW + 1), Err(ShatterError::InvalidParameter));
        assert!(monitor.rearm(NOW + WEEK).is_ok());
        assert!(monitor.is_armed());
        std::fs::remove_file(&path).expect("cleanup");
    }
}
