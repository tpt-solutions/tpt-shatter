// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! In-band canary detection: watches the reads and deletes the vault router performs.
//!
//! Nothing in the system touches a canary on purpose, except rotation and erasure. Those
//! use the router's maintenance methods, which are not observed. So any observed read or
//! delete of a canary FragmentId is suspicious. [`CanaryWatch`] is attached to the router
//! as an [`AccessObserver`] and queues an [`Alarm`] for each such access. The caller
//! drains the queue with [`CanaryWatch::take_alarms`], and [`crate::CanaryMonitor`] feeds
//! the result to the alarm gate.
//!
//! Limits, by design:
//! - Writes are not observed. Ingestion writes real data, and canary injection writes
//!   canaries. A canary that is overwritten is not detected.
//! - Direct access to vault files on the host, and any caller that bypasses the router,
//!   are not seen.
//! - After a rotation the caller must call [`CanaryWatch::replace`] with the new plan.
//!   Canaries from the previous epoch are then no longer watched.

use std::sync::Mutex;

use tpt_shatter_common::{FragmentId, ShatterError, VaultId};
use tpt_shatter_vault_client::{Access, AccessObserver};

use crate::{Alarm, CanaryIds, CanaryPlan, Detector};

/// Watches observed accesses for the canaries of one epoch.
pub struct CanaryWatch {
    detector: Mutex<Detector>,
    pending: Mutex<Vec<Alarm>>,
}

impl CanaryWatch {
    /// Watches the canaries of `plan`.
    pub fn new(plan: &CanaryPlan) -> Result<Self, ShatterError> {
        Ok(Self {
            detector: Mutex::new(Detector::new(plan)?),
            pending: Mutex::new(Vec::new()),
        })
    }

    /// Watches nothing, until [`CanaryWatch::replace_ids`] supplies a list. Used by a host that
    /// starts before its first canary list arrives.
    #[must_use]
    pub fn unwatched() -> Self {
        Self {
            detector: Mutex::new(Detector::from_entries(&[])),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Watches the canaries listed in `ids`. Needs no canary key, so it suits a host that
    /// only reads canaries.
    #[must_use]
    pub fn from_ids(ids: &CanaryIds) -> Self {
        Self {
            detector: Mutex::new(Detector::from_entries(ids.entries())),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Switches to the canaries of `plan`, after a rotation. Alarms already queued are kept.
    pub fn replace(&self, plan: &CanaryPlan) -> Result<(), ShatterError> {
        let next = Detector::new(plan)?;
        *self.detector.lock().map_err(|_| ShatterError::Internal)? = next;
        Ok(())
    }

    /// Switches to the canaries listed in `ids`. Alarms already queued are kept.
    pub fn replace_ids(&self, ids: &CanaryIds) -> Result<(), ShatterError> {
        let next = Detector::from_entries(ids.entries());
        *self.detector.lock().map_err(|_| ShatterError::Internal)? = next;
        Ok(())
    }

    /// Removes and returns every alarm queued since the last call.
    pub fn take_alarms(&self) -> Result<Vec<Alarm>, ShatterError> {
        let mut pending = self.pending.lock().map_err(|_| ShatterError::Internal)?;
        Ok(std::mem::take(&mut *pending))
    }

    /// Puts alarms back in the queue, so a failed response can be retried.
    pub(crate) fn requeue(&self, alarms: Vec<Alarm>) -> Result<(), ShatterError> {
        self.pending
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .extend(alarms);
        Ok(())
    }
}

impl AccessObserver for CanaryWatch {
    /// Never fails the access. A poisoned lock drops the observation, so this is a
    /// best-effort signal rather than a guarantee.
    fn on_access(&self, vault: VaultId, id: &FragmentId, _access: Access) {
        let Ok(detector) = self.detector.lock() else {
            return;
        };
        let hits = detector.scan(&[(vault, id.clone())]);
        drop(detector);
        if hits.is_empty() {
            return;
        }
        if let Ok(mut pending) = self.pending.lock() {
            pending.extend(hits);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanaryRotation, refresh_canaries};
    use std::sync::Arc;
    use tpt_shatter_common::{FRAGMENT_ID_LEN, ShatterSchema};
    use tpt_shatter_vault_client::{
        BreakerConfig, Guarded, MemoryVault, Router, derive_fragment_id, system_clock,
    };

    const MASTER: [u8; 32] = [0x71; 32];
    const DERIVATION: [u8; 32] = [0x72; 32];
    const WEEK: u64 = 7 * 24 * 3600;
    const NOW: u64 = 20 * WEEK + 1;

    fn schema() -> ShatterSchema {
        ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("schema")
    }

    /// A router with memory vaults and a watch attached. Returns the router and watch.
    fn watched_router(plan: &CanaryPlan) -> (Router, Arc<CanaryWatch>) {
        let watch = Arc::new(CanaryWatch::new(plan).expect("watch"));
        let guards = VaultId::ALL
            .iter()
            .map(|v| {
                Guarded::new(
                    Box::new(MemoryVault::new(*v)),
                    BreakerConfig {
                        attempts: 1,
                        ..BreakerConfig::default()
                    },
                    system_clock(),
                )
            })
            .collect();
        let observer: Arc<dyn AccessObserver> = Arc::clone(&watch) as Arc<dyn AccessObserver>;
        let router = Router::new(guards).expect("router").with_observer(observer);
        (router, watch)
    }

    fn canary_id(plan: &CanaryPlan, index: usize, vault: VaultId) -> FragmentId {
        let shard = plan.shard(index).expect("shard");
        derive_fragment_id(&DERIVATION, &shard, vault).expect("id")
    }

    fn real_id(byte: u8) -> FragmentId {
        FragmentId::from_bytes([byte; FRAGMENT_ID_LEN])
    }

    #[test]
    fn reading_a_canary_raises_an_alarm_for_that_vault_and_index() {
        let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let plan = rotation.plan_at(NOW).expect("plan");
        let (router, watch) = watched_router(&plan);
        refresh_canaries(&rotation, &schema(), &router, &DERIVATION, None, NOW).expect("refresh");

        let _ = router.get(VaultId::B, &canary_id(&plan, 1, VaultId::B));
        let alarms = watch.take_alarms().expect("take");
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].vault, VaultId::B);
        assert_eq!(alarms[0].index, 1);
    }

    #[test]
    fn deleting_a_canary_through_the_router_raises_an_alarm() {
        let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let plan = rotation.plan_at(NOW).expect("plan");
        let (router, watch) = watched_router(&plan);
        refresh_canaries(&rotation, &schema(), &router, &DERIVATION, None, NOW).expect("refresh");

        let _ = router.delete(VaultId::A, &canary_id(&plan, 0, VaultId::A));
        let alarms = watch.take_alarms().expect("take");
        assert_eq!(
            alarms,
            vec![Alarm {
                vault: VaultId::A,
                index: 0
            }]
        );
    }

    #[test]
    fn reading_an_ordinary_id_raises_nothing() {
        let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let plan = rotation.plan_at(NOW).expect("plan");
        let (router, watch) = watched_router(&plan);
        refresh_canaries(&rotation, &schema(), &router, &DERIVATION, None, NOW).expect("refresh");

        let _ = router.get(VaultId::A, &real_id(0x42));
        assert_eq!(watch.take_alarms().expect("take"), Vec::new());
    }

    #[test]
    fn rotation_does_not_alarm_on_its_own_erasure() {
        let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
        let first = rotation.plan_at(NOW).expect("plan");
        let (router, watch) = watched_router(&first);
        refresh_canaries(&rotation, &schema(), &router, &DERIVATION, None, NOW).expect("first");

        let next_now = NOW + WEEK;
        let next = rotation.plan_at(next_now).expect("plan");
        refresh_canaries(
            &rotation,
            &schema(),
            &router,
            &DERIVATION,
            Some(20),
            next_now,
        )
        .expect("second");
        watch.replace(&next).expect("replace");
        assert_eq!(watch.take_alarms().expect("take"), Vec::new());

        // The new epoch's canaries are watched; the old ones no longer are.
        let _ = router.get(VaultId::C, &canary_id(&next, 0, VaultId::C));
        let _ = router.get(VaultId::C, &canary_id(&first, 0, VaultId::C));
        let alarms = watch.take_alarms().expect("take");
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].vault, VaultId::C);
    }
}
