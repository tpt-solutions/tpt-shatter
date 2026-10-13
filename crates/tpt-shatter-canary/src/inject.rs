// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Writes the current epoch's canaries to the vaults and removes the previous epoch's.

use tpt_shatter_common::{ShatterError, ShatterSchema};
use tpt_shatter_shredder::{Shredder, erase};
use tpt_shatter_vault_client::Router;

use crate::CanaryRotation;

/// Brings the vaults up to date with the canary epoch containing `now`.
///
/// Returns `Some(epoch)` when canaries were refreshed, or `None` when `last_epoch`
/// already matches. The new canaries are written first, then the previous epoch's
/// canaries are erased, so the vaults never lack canaries. A failure at any step returns
/// an error without advancing, so the caller keeps its old `last_epoch`. The next call
/// then repeats the work, which is safe because writes and erases are idempotent.
///
/// The caller must rebuild its [`crate::Detector`] from the new plan after a refresh.
pub fn refresh_canaries(
    rotation: &CanaryRotation,
    schema: &ShatterSchema,
    router: &Router,
    derivation_key: &[u8; 32],
    last_epoch: Option<u64>,
    now: u64,
) -> Result<Option<u64>, ShatterError> {
    if !rotation.needs_refresh(last_epoch, now)? {
        return Ok(None);
    }
    let current = rotation.epoch(now)?;
    let plan = rotation.plan_for_epoch(current)?;
    let shredder = Shredder::new(schema, router, *derivation_key);
    for index in 0..rotation.count() {
        shredder.shred(&plan.shard(index)?, plan.record(schema, index)?)?;
    }
    if let Some(old) = last_epoch {
        let old_plan = rotation.plan_for_epoch(old)?;
        for index in 0..rotation.count() {
            erase(router, derivation_key, &old_plan.shard(index)?)?;
        }
    }
    Ok(Some(current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tpt_shatter_common::VaultId;
    use tpt_shatter_vault_client::{BreakerConfig, Guarded, MemoryVault, system_clock};

    const MASTER: [u8; 32] = [0x61; 32];
    const DERIVATION: [u8; 32] = [0x62; 32];
    const WEEK: u64 = 7 * 24 * 3600;
    const COUNT: usize = 2;

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

    fn fixture() -> (Router, Vec<Arc<MemoryVault>>) {
        let vaults: Vec<Arc<MemoryVault>> = VaultId::ALL
            .iter()
            .map(|v| Arc::new(MemoryVault::new(*v)))
            .collect();
        let guards = vaults
            .iter()
            .map(|v| {
                Guarded::new(
                    Box::new(Arc::clone(v)),
                    BreakerConfig {
                        attempts: 1,
                        ..BreakerConfig::default()
                    },
                    system_clock(),
                )
            })
            .collect();
        (Router::new(guards).expect("router"), vaults)
    }

    fn rotation() -> CanaryRotation {
        CanaryRotation::new(MASTER, DERIVATION, COUNT, WEEK).expect("rotation")
    }

    fn rows(vaults: &[Arc<MemoryVault>]) -> Vec<usize> {
        vaults
            .iter()
            .map(|v| v.row_count().expect("count"))
            .collect()
    }

    #[test]
    fn first_refresh_writes_one_fragment_per_canary_per_vault() {
        let (router, vaults) = fixture();
        let epoch = refresh_canaries(
            &rotation(),
            &schema(),
            &router,
            &DERIVATION,
            None,
            10 * WEEK,
        )
        .expect("refresh");
        assert_eq!(epoch, Some(10));
        assert_eq!(rows(&vaults), [COUNT, COUNT, COUNT]);
    }

    #[test]
    fn a_repeat_in_the_same_epoch_does_nothing() {
        let (router, vaults) = fixture();
        let r = rotation();
        refresh_canaries(&r, &schema(), &router, &DERIVATION, None, 10 * WEEK).expect("first");
        let again = refresh_canaries(&r, &schema(), &router, &DERIVATION, Some(10), 10 * WEEK + 5)
            .expect("again");
        assert_eq!(again, None);
        assert_eq!(rows(&vaults), [COUNT, COUNT, COUNT]);
    }

    #[test]
    fn moving_to_the_next_epoch_replaces_the_old_canaries() {
        let (router, vaults) = fixture();
        let r = rotation();
        refresh_canaries(&r, &schema(), &router, &DERIVATION, None, 10 * WEEK).expect("first");
        let next = refresh_canaries(&r, &schema(), &router, &DERIVATION, Some(10), 11 * WEEK)
            .expect("second");
        assert_eq!(next, Some(11));
        // One generation only: the old epoch's rows were erased.
        assert_eq!(rows(&vaults), [COUNT, COUNT, COUNT]);
    }
}
