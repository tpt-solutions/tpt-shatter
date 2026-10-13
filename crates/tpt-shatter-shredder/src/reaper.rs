// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Background reaping: runs [`Shredder::reap`] on an interval until told to stop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tpt_shatter_common::{AlertLog, ShatterError};

use crate::shred::{ReapReport, Shredder};

/// How often a stop flag is checked while waiting between passes.
const POLL: Duration = Duration::from_millis(10);

/// Reaps every `interval` until `stop` is set, calling `on_report` after each pass.
///
/// A pass that abandons orphans (`abandoned > 0`) writes a `reap_abandoned` line to
/// `alerts` when one is given. A failed alert write ends the loop with an error, because
/// an unrecorded abandonment is worse than a stopped reaper. `on_report` runs after the
/// alert, so a caller can add its own notification.
///
/// Each pass runs `reap(max_attempts)`. A failed pass also ends the loop, because the
/// queue may not be durable at that point.
///
/// Runs on the calling thread. Stop it by setting `stop` from another thread, or from
/// inside `on_report`.
pub fn run_reaper<F>(
    shredder: &Shredder<'_>,
    interval: Duration,
    max_attempts: u32,
    stop: &AtomicBool,
    alerts: Option<&AlertLog>,
    mut on_report: F,
) -> Result<(), ShatterError>
where
    F: FnMut(ReapReport),
{
    if interval.is_zero() || max_attempts == 0 {
        return Err(ShatterError::InvalidParameter);
    }
    while !stop.load(Ordering::SeqCst) {
        let report = shredder.reap(max_attempts)?;
        if report.abandoned > 0 {
            if let Some(log) = alerts {
                let count = report.abandoned.to_string();
                log.append("reap_abandoned", now_secs(), &[("count", &count)])?;
            }
        }
        on_report(report);
        let next = Instant::now() + interval;
        while Instant::now() < next && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(POLL);
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Arc;
    use tpt_shatter_common::{FragmentId, Record, ShardKey, ShatterError, ShatterSchema, VaultId};
    use tpt_shatter_vault_client::{
        BreakerConfig, Guarded, MemoryVault, Router, VaultBackend, system_clock,
    };
    use zeroize::Zeroizing;

    const KEY: [u8; 32] = [0x42; 32];

    /// Refuses every delete, so a compensating delete always fails and orphans pile up.
    struct NoDeletes(Arc<MemoryVault>);

    impl VaultBackend for NoDeletes {
        fn vault(&self) -> VaultId {
            self.0.vault()
        }
        fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
            self.0.put(id, bytes)
        }
        fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
            self.0.get(id)
        }
        fn delete(&self, _: &FragmentId) -> Result<bool, ShatterError> {
            Err(ShatterError::VaultUnavailable {
                vault: self.0.vault(),
            })
        }
    }

    /// Vault B is down, so the write fails, and vault A's compensating delete is refused.
    fn stranded_shredder_fixture() -> (ShatterSchema, Router, Arc<MemoryVault>) {
        let schema = ShatterSchema::new(1, [("name", VaultId::A), ("birth_year", VaultId::B)])
            .expect("schema");
        let vault_a = Arc::new(MemoryVault::new(VaultId::A));
        let vault_b = Arc::new(MemoryVault::new(VaultId::B));
        vault_b.set_available(false);
        let config = BreakerConfig {
            attempts: 1,
            failure_threshold: 1000,
            ..BreakerConfig::default()
        };
        let guards = vec![
            Guarded::new(
                Box::new(NoDeletes(Arc::clone(&vault_a))),
                config,
                system_clock(),
            ),
            Guarded::new(Box::new(Arc::clone(&vault_b)), config, system_clock()),
            Guarded::new(
                Box::new(MemoryVault::new(VaultId::C)),
                config,
                system_clock(),
            ),
        ];
        let router = Router::new(guards).expect("router");
        (schema, router, vault_a)
    }

    fn record() -> Record {
        let mut r = Record::new();
        r.insert("name", "A. Example");
        r.insert("birth_year", "1990");
        r
    }

    fn temp_alert_path(name: &str) -> std::path::PathBuf {
        let nanos = now_secs_nanos();
        std::env::temp_dir().join(format!("tpt-shatter-reaper-{name}-{nanos}.jsonl"))
    }

    fn now_secs_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    }

    #[test]
    fn rejects_zero_interval_and_zero_attempts() {
        let (schema, router, _) = stranded_shredder_fixture();
        let shredder = Shredder::new(&schema, &router, KEY);
        let stop = AtomicBool::new(false);
        assert_eq!(
            run_reaper(&shredder, Duration::ZERO, 3, &stop, None, |_| {}),
            Err(ShatterError::InvalidParameter)
        );
        assert_eq!(
            run_reaper(&shredder, Duration::from_millis(1), 0, &stop, None, |_| {}),
            Err(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn reports_each_pass_and_stops_when_asked() {
        let (schema, router, _) = stranded_shredder_fixture();
        let shredder = Shredder::new(&schema, &router, KEY);
        let stop = AtomicBool::new(false);
        let passes = Cell::new(0);
        run_reaper(&shredder, Duration::from_millis(1), 3, &stop, None, |_| {
            passes.set(passes.get() + 1);
            if passes.get() == 3 {
                stop.store(true, Ordering::SeqCst);
            }
        })
        .expect("run");
        assert_eq!(passes.get(), 3);
    }

    #[test]
    fn an_abandoned_orphan_is_reported_and_alerted() {
        let (schema, router, vault_a) = stranded_shredder_fixture();
        let shredder = Shredder::new(&schema, &router, KEY);
        let shard = ShardKey::from_bytes([9; 32]);
        assert!(shredder.shred(&shard, record()).is_err());
        assert_eq!(shredder.pending_orphans(), Ok(1));
        // The orphan row is still in vault A, since its delete was refused.
        assert_eq!(vault_a.row_count(), Ok(1));

        let path = temp_alert_path("abandoned");
        let log = AlertLog::open(&path).expect("open");
        let stop = AtomicBool::new(false);
        let abandoned = Cell::new(0);
        // One attempt allowed, and the delete still fails, so the orphan is abandoned.
        run_reaper(
            &shredder,
            Duration::from_millis(1),
            1,
            &stop,
            Some(&log),
            |report| {
                abandoned.set(abandoned.get() + report.abandoned);
                stop.store(true, Ordering::SeqCst);
            },
        )
        .expect("run");
        let alerts = std::fs::read_to_string(&path).expect("read alerts");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(abandoned.get(), 1);
        assert_eq!(shredder.pending_orphans(), Ok(0));
        assert!(alerts.contains(r#""kind":"reap_abandoned""#));
        assert!(alerts.contains(r#""count":"1""#));
    }
}
