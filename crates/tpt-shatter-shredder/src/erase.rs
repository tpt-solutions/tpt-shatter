// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use tpt_shatter_common::{ShardKey, ShatterError, VaultId};
use tpt_shatter_vault_client::{Router, derive_fragment_id};

/// Outcome of an [`erase`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EraseReport {
    /// Fragments removed by this call. Zero on a repeat call.
    pub rows_removed: usize,
    /// True when a read-back after deletion found no fragment in any vault.
    pub verified: bool,
}

/// Deletes every fragment for `shard` across all vaults (GDPR erasure).
///
/// This is idempotent. A vault error stops the run and returns the error. Calling
/// again with the same arguments finishes the job, because deleting a missing row is
/// not an error. Backups are not covered here (see the Phase 11 backup-handling item).
pub fn erase(
    router: &Router,
    derivation_key: &[u8],
    shard: &ShardKey,
) -> Result<EraseReport, ShatterError> {
    let mut rows_removed = 0;
    for vault in VaultId::ALL {
        let id = derive_fragment_id(derivation_key, shard, vault)?;
        if router.delete(vault, &id)? {
            rows_removed += 1;
        }
    }

    let mut verified = true;
    for vault in VaultId::ALL {
        let id = derive_fragment_id(derivation_key, shard, vault)?;
        if router.get(vault, &id)?.is_some() {
            verified = false;
        }
    }
    Ok(EraseReport {
        rows_removed,
        verified,
    })
}
