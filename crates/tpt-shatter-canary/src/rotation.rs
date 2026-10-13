// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Canary rotation schedule: which epoch is current, and whether canaries must be refreshed.

use tpt_shatter_common::{ShatterError, VaultId};
use zeroize::Zeroizing;

use crate::{CanaryPlan, epoch_at};

/// Derives the canary plan for the current epoch from fixed master secrets.
///
/// Each epoch of `period_secs` seconds yields fresh canaries. The schedule itself has
/// no state, so any process holding the same secrets computes the same plan for a
/// given time.
pub struct CanaryRotation {
    master_key: Zeroizing<[u8; 32]>,
    derivation_key: Zeroizing<[u8; 32]>,
    count: usize,
    period_secs: u64,
}

impl CanaryRotation {
    /// Creates a schedule. `count` must be positive and `period_secs` non-zero.
    pub fn new(
        master_key: [u8; 32],
        derivation_key: [u8; 32],
        count: usize,
        period_secs: u64,
    ) -> Result<Self, ShatterError> {
        if count == 0 || period_secs == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self {
            master_key: Zeroizing::new(master_key),
            derivation_key: Zeroizing::new(derivation_key),
            count,
            period_secs,
        })
    }

    /// The epoch containing `now` (Unix seconds).
    pub fn epoch(&self, now: u64) -> Result<u64, ShatterError> {
        epoch_at(now, self.period_secs)
    }

    /// The canary plan for the epoch containing `now`.
    pub fn plan_at(&self, now: u64) -> Result<CanaryPlan, ShatterError> {
        self.plan_for_epoch(self.epoch(now)?)
    }

    /// The canary plan for a given epoch. Used to find the canaries of an older epoch.
    pub fn plan_for_epoch(&self, epoch: u64) -> Result<CanaryPlan, ShatterError> {
        CanaryPlan::for_epoch(*self.master_key, *self.derivation_key, self.count, epoch)
    }

    /// Whether canaries injected in `last_epoch` must be replaced at time `now`.
    ///
    /// `None` means nothing has been injected yet, so a refresh is due.
    pub fn needs_refresh(&self, last_epoch: Option<u64>, now: u64) -> Result<bool, ShatterError> {
        Ok(last_epoch != Some(self.epoch(now)?))
    }

    /// Canaries per epoch. Each vault receives one fragment per canary.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// The vaults that canaries are written to.
    #[must_use]
    pub fn vaults(&self) -> [VaultId; 3] {
        VaultId::ALL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [0x31; 32];
    const DERIVATION: [u8; 32] = [0x32; 32];
    const WEEK: u64 = 7 * 24 * 3600;

    #[test]
    fn rejects_zero_count_and_zero_period() {
        assert_eq!(
            CanaryRotation::new(MASTER, DERIVATION, 0, WEEK).err(),
            Some(ShatterError::InvalidParameter)
        );
        assert_eq!(
            CanaryRotation::new(MASTER, DERIVATION, 2, 0).err(),
            Some(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn plan_is_stable_within_an_epoch_and_changes_across_epochs() {
        let r = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let start = 10 * WEEK;
        let a = r.plan_at(start).expect("plan");
        let b = r.plan_at(start + WEEK - 1).expect("plan");
        let c = r.plan_at(start + WEEK).expect("plan");
        assert_eq!(a.prefix().expect("p"), b.prefix().expect("p"));
        assert_ne!(a.prefix().expect("p"), c.prefix().expect("p"));
    }

    #[test]
    fn refresh_is_due_when_nothing_was_injected_or_the_epoch_moved() {
        let r = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let now = 10 * WEEK + 5;
        assert_eq!(r.needs_refresh(None, now), Ok(true));
        assert_eq!(r.needs_refresh(Some(10), now), Ok(false));
        assert_eq!(r.needs_refresh(Some(9), now), Ok(true));
    }
}
