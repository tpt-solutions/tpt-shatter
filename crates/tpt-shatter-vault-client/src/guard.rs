// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_shatter_common::{FragmentId, ShatterError, VaultId};
use zeroize::Zeroizing;

use crate::backend::VaultBackend;

/// Returns the current Unix time in seconds.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

/// A [`Clock`] backed by the system time. A pre-epoch clock reads as 0.
#[must_use]
pub fn system_clock() -> Clock {
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// Tuning for the per-vault circuit breaker and retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Consecutive failed operations before the breaker opens.
    pub failure_threshold: u32,
    /// Seconds the breaker stays open before allowing a trial call.
    pub cooldown_secs: u64,
    /// Total attempts per operation (1 means no retry). Retries are immediate; backoff is pending.
    pub attempts: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown_secs: 30,
            attempts: 2,
        }
    }
}

/// Circuit-breaker state as reported to operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Calls flow normally.
    Closed,
    /// Calls are rejected without touching the vault.
    Open,
    /// The cooldown has passed. The next call is a trial.
    HalfOpen,
}

/// Connection status for one vault, for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStatus {
    /// The vault being reported.
    pub vault: VaultId,
    /// Current breaker state.
    pub state: BreakerState,
    /// Consecutive failed operations since the last success.
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Closed,
    Open { until: u64 },
    HalfOpen,
}

#[derive(Debug)]
struct Breaker {
    phase: Phase,
    failures: u32,
}

impl Breaker {
    fn allow(&mut self, now: u64) -> bool {
        match self.phase {
            Phase::Closed | Phase::HalfOpen => true,
            Phase::Open { until } if now >= until => {
                self.phase = Phase::HalfOpen;
                true
            }
            Phase::Open { .. } => false,
        }
    }

    fn record_success(&mut self) {
        self.phase = Phase::Closed;
        self.failures = 0;
    }

    fn record_failure(&mut self, now: u64, config: BreakerConfig) {
        self.failures = self.failures.saturating_add(1);
        // A failed trial call reopens immediately. Otherwise the threshold applies.
        if matches!(self.phase, Phase::HalfOpen) || self.failures >= config.failure_threshold {
            self.phase = Phase::Open {
                until: now.saturating_add(config.cooldown_secs),
            };
        }
    }

    fn state(&self) -> BreakerState {
        match self.phase {
            Phase::Closed => BreakerState::Closed,
            Phase::Open { .. } => BreakerState::Open,
            Phase::HalfOpen => BreakerState::HalfOpen,
        }
    }
}

/// A vault backend wrapped with a circuit breaker and bounded retries.
///
/// Only [`ShatterError::VaultUnavailable`] counts as a failure. Logic errors such as
/// `InvalidParameter` pass through and do not trip the breaker.
pub struct Guarded {
    backend: Box<dyn VaultBackend>,
    config: BreakerConfig,
    clock: Clock,
    breaker: Mutex<Breaker>,
}

impl Guarded {
    /// Wraps `backend` with the given breaker settings and clock.
    #[must_use]
    pub fn new(backend: Box<dyn VaultBackend>, config: BreakerConfig, clock: Clock) -> Self {
        Self {
            backend,
            config,
            clock,
            breaker: Mutex::new(Breaker {
                phase: Phase::Closed,
                failures: 0,
            }),
        }
    }

    /// The vault this guard serves.
    #[must_use]
    pub fn vault(&self) -> VaultId {
        self.backend.vault()
    }

    /// Current status for observability.
    pub fn status(&self) -> Result<VaultStatus, ShatterError> {
        let breaker = self.lock()?;
        Ok(VaultStatus {
            vault: self.vault(),
            state: breaker.state(),
            consecutive_failures: breaker.failures,
        })
    }

    /// Stores a fragment through the breaker.
    pub fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
        self.call(|b| b.put(id, bytes))
    }

    /// Reads a fragment through the breaker.
    pub fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
        self.call(|b| b.get(id))
    }

    /// Deletes a fragment through the breaker.
    pub fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
        self.call(|b| b.delete(id))
    }

    fn call<T>(
        &self,
        op: impl Fn(&dyn VaultBackend) -> Result<T, ShatterError>,
    ) -> Result<T, ShatterError> {
        let now = (self.clock)();
        if !self.lock()?.allow(now) {
            return Err(ShatterError::VaultUnavailable {
                vault: self.vault(),
            });
        }
        let mut last_error = ShatterError::Internal;
        for _ in 0..self.config.attempts.max(1) {
            match op(self.backend.as_ref()) {
                Ok(value) => {
                    self.lock()?.record_success();
                    return Ok(value);
                }
                Err(e @ ShatterError::VaultUnavailable { .. }) => last_error = e,
                Err(other) => return Err(other),
            }
        }
        self.lock()?.record_failure(now, self.config);
        Err(last_error)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Breaker>, ShatterError> {
        self.breaker.lock().map_err(|_| ShatterError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryVault;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Shares a `MemoryVault` so a test can flip its availability after wrapping it.
    struct Shared(Arc<MemoryVault>);

    impl VaultBackend for Shared {
        fn vault(&self) -> VaultId {
            self.0.vault()
        }
        fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
            self.0.put(id, bytes)
        }
        fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
            self.0.get(id)
        }
        fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
            self.0.delete(id)
        }
    }

    fn setup(config: BreakerConfig) -> (Guarded, Arc<MemoryVault>, Arc<AtomicU64>) {
        let vault = Arc::new(MemoryVault::new(VaultId::A));
        let now = Arc::new(AtomicU64::new(1_000));
        let clock_now = Arc::clone(&now);
        let clock: Clock = Box::new(move || clock_now.load(Ordering::SeqCst));
        let guarded = Guarded::new(Box::new(Shared(Arc::clone(&vault))), config, clock);
        (guarded, vault, now)
    }

    fn id() -> FragmentId {
        FragmentId::from_bytes([5; 32])
    }

    #[test]
    fn healthy_calls_pass_through() {
        let (g, _, _) = setup(BreakerConfig::default());
        g.put(&id(), b"x").expect("put");
        assert_eq!(g.status().expect("status").state, BreakerState::Closed);
    }

    #[test]
    fn retries_once_then_reports_unavailable() {
        let (g, vault, _) = setup(BreakerConfig::default());
        vault.set_available(false);
        assert_eq!(
            g.put(&id(), b"x"),
            Err(ShatterError::VaultUnavailable { vault: VaultId::A })
        );
        assert_eq!(g.status().expect("status").consecutive_failures, 1);
    }

    #[test]
    fn opens_after_threshold_and_rejects_without_calling_vault() {
        let config = BreakerConfig {
            failure_threshold: 2,
            cooldown_secs: 30,
            attempts: 1,
        };
        let (g, vault, _) = setup(config);
        vault.set_available(false);
        let _ = g.put(&id(), b"x");
        let _ = g.put(&id(), b"x");
        assert_eq!(g.status().expect("status").state, BreakerState::Open);
        // Recovery does not matter while the breaker is open.
        vault.set_available(true);
        assert!(g.put(&id(), b"x").is_err());
        assert_eq!(vault.row_count(), Ok(0));
    }

    #[test]
    fn half_open_trial_closes_on_success() {
        let config = BreakerConfig {
            failure_threshold: 1,
            cooldown_secs: 10,
            attempts: 1,
        };
        let (g, vault, now) = setup(config);
        vault.set_available(false);
        let _ = g.put(&id(), b"x");
        assert_eq!(g.status().expect("status").state, BreakerState::Open);
        vault.set_available(true);
        now.store(1_010, Ordering::SeqCst);
        g.put(&id(), b"x").expect("trial succeeds");
        assert_eq!(g.status().expect("status").state, BreakerState::Closed);
    }

    #[test]
    fn half_open_failure_reopens() {
        let config = BreakerConfig {
            failure_threshold: 1,
            cooldown_secs: 10,
            attempts: 1,
        };
        let (g, vault, now) = setup(config);
        vault.set_available(false);
        let _ = g.put(&id(), b"x");
        now.store(1_010, Ordering::SeqCst);
        assert!(g.put(&id(), b"x").is_err());
        assert_eq!(g.status().expect("status").state, BreakerState::Open);
    }

    /// A backend that always reports a logic error, not an outage.
    struct Rejecting;

    impl VaultBackend for Rejecting {
        fn vault(&self) -> VaultId {
            VaultId::B
        }
        fn put(&self, _: &FragmentId, _: &[u8]) -> Result<(), ShatterError> {
            Err(ShatterError::InvalidParameter)
        }
        fn get(&self, _: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
            Err(ShatterError::InvalidParameter)
        }
        fn delete(&self, _: &FragmentId) -> Result<bool, ShatterError> {
            Err(ShatterError::InvalidParameter)
        }
    }

    #[test]
    fn logic_errors_pass_through_without_tripping_the_breaker() {
        let config = BreakerConfig {
            failure_threshold: 1,
            cooldown_secs: 10,
            attempts: 3,
        };
        let g = Guarded::new(Box::new(Rejecting), config, system_clock());
        for _ in 0..3 {
            assert_eq!(g.put(&id(), b"x"), Err(ShatterError::InvalidParameter));
        }
        let status = g.status().expect("status");
        assert_eq!(status.state, BreakerState::Closed);
        assert_eq!(status.consecutive_failures, 0);
    }
}
