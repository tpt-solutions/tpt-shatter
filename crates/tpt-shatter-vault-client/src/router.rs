// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::BTreeMap;

use tpt_shatter_common::{FragmentId, ShatterError, VaultId};
use zeroize::Zeroizing;

use crate::guard::{Guarded, VaultStatus};

/// Routes each operation to exactly one vault.
///
/// A router holds one guarded backend per [`VaultId`], and every method names a
/// single vault. There is no method that touches more than one vault, so
/// cross-vault joins cannot be written against this type.
pub struct Router {
    vaults: BTreeMap<VaultId, Guarded>,
}

impl Router {
    /// Builds a router from exactly one guard per vault.
    ///
    /// Returns [`ShatterError::InvalidParameter`] if a vault is missing or repeated.
    pub fn new(vaults: Vec<Guarded>) -> Result<Self, ShatterError> {
        let mut map = BTreeMap::new();
        for guard in vaults {
            if map.insert(guard.vault(), guard).is_some() {
                return Err(ShatterError::InvalidParameter);
            }
        }
        if map.len() != VaultId::ALL.len() {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self { vaults: map })
    }

    fn vault(&self, vault: VaultId) -> Result<&Guarded, ShatterError> {
        self.vaults.get(&vault).ok_or(ShatterError::UnknownVault)
    }

    /// Stores a fragment in `vault`.
    pub fn put(&self, vault: VaultId, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
        self.vault(vault)?.put(id, bytes)
    }

    /// Reads a fragment from `vault`.
    pub fn get(
        &self,
        vault: VaultId,
        id: &FragmentId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
        self.vault(vault)?.get(id)
    }

    /// Deletes a fragment from `vault`. Returns `true` if a row was removed.
    pub fn delete(&self, vault: VaultId, id: &FragmentId) -> Result<bool, ShatterError> {
        self.vault(vault)?.delete(id)
    }

    /// Breaker status for every vault, in label order.
    pub fn statuses(&self) -> Result<Vec<VaultStatus>, ShatterError> {
        self.vaults.values().map(Guarded::status).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryVault;
    use crate::guard::{BreakerConfig, system_clock};

    fn guard(v: VaultId) -> Guarded {
        Guarded::new(
            Box::new(MemoryVault::new(v)),
            BreakerConfig::default(),
            system_clock(),
        )
    }

    fn full_router() -> Router {
        Router::new(VaultId::ALL.iter().map(|v| guard(*v)).collect()).expect("router")
    }

    #[test]
    fn requires_exactly_one_guard_per_vault() {
        assert!(Router::new(vec![guard(VaultId::A), guard(VaultId::B)]).is_err());
        assert!(
            Router::new(vec![
                guard(VaultId::A),
                guard(VaultId::A),
                guard(VaultId::B),
                guard(VaultId::C)
            ])
            .is_err()
        );
        assert!(Router::new(VaultId::ALL.iter().map(|v| guard(*v)).collect()).is_ok());
    }

    #[test]
    fn writes_land_in_exactly_one_vault() {
        let r = full_router();
        let id = FragmentId::from_bytes([9; 32]);
        r.put(VaultId::B, &id, b"fragment").expect("put");
        assert!(r.get(VaultId::B, &id).expect("get").is_some());
        assert!(r.get(VaultId::A, &id).expect("get").is_none());
        assert!(r.get(VaultId::C, &id).expect("get").is_none());
    }

    #[test]
    fn statuses_cover_all_vaults_in_order() {
        let statuses = full_router().statuses().expect("statuses");
        let order: Vec<_> = statuses.iter().map(|s| s.vault).collect();
        assert_eq!(order, VaultId::ALL);
    }
}
