// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use tpt_shatter_common::{FragmentId, ShatterError, VaultId};
use zeroize::Zeroizing;

/// Storage for one vault. Implementations must be safe to share across threads.
///
/// Every method takes a single [`FragmentId`]. Nothing here can span vaults.
pub trait VaultBackend: Send + Sync {
    /// The vault this backend serves.
    fn vault(&self) -> VaultId;

    /// Stores `bytes` under `id`, replacing any existing value. Replacing with the
    /// same bytes is idempotent, which makes shredder retries safe.
    fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError>;

    /// Returns the bytes stored under `id`, or `None` if absent.
    fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError>;

    /// Removes `id`. Returns `true` if a row was removed. Deleting a missing row is not an error.
    fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError>;
}

type Rows = HashMap<[u8; 32], Zeroizing<Vec<u8>>>;

/// In-memory vault for tests. It can simulate an outage with [`MemoryVault::set_available`].
pub struct MemoryVault {
    vault: VaultId,
    rows: Mutex<Rows>,
    available: AtomicBool,
}

impl MemoryVault {
    /// Creates an empty, available vault.
    #[must_use]
    pub fn new(vault: VaultId) -> Self {
        Self {
            vault,
            rows: Mutex::new(HashMap::new()),
            available: AtomicBool::new(true),
        }
    }

    /// Simulates an outage (`false`) or recovery (`true`).
    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }

    /// Number of stored rows. Useful for asserting placement in tests.
    pub fn row_count(&self) -> Result<usize, ShatterError> {
        Ok(self.lock()?.len())
    }

    fn check_available(&self) -> Result<(), ShatterError> {
        if self.available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ShatterError::VaultUnavailable { vault: self.vault })
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Rows>, ShatterError> {
        self.rows.lock().map_err(|_| ShatterError::Internal)
    }
}

impl VaultBackend for MemoryVault {
    fn vault(&self) -> VaultId {
        self.vault
    }

    fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
        self.check_available()?;
        self.lock()?
            .insert(*id.as_bytes(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }

    fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
        self.check_available()?;
        Ok(self
            .lock()?
            .get(id.as_bytes())
            .map(|bytes| Zeroizing::new(bytes.to_vec())))
    }

    fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
        self.check_available()?;
        Ok(self.lock()?.remove(id.as_bytes()).is_some())
    }
}

/// Lets a shared backend (for example one a test keeps a handle to) be wrapped in a guard.
impl<T: VaultBackend + ?Sized> VaultBackend for std::sync::Arc<T> {
    fn vault(&self) -> VaultId {
        (**self).vault()
    }

    fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
        (**self).put(id, bytes)
    }

    fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
        (**self).get(id)
    }

    fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
        (**self).delete(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> FragmentId {
        FragmentId::from_bytes([byte; 32])
    }

    #[test]
    fn put_get_delete_round_trip() {
        let v = MemoryVault::new(VaultId::A);
        v.put(&id(1), b"payload").expect("put");
        assert_eq!(
            v.get(&id(1)).expect("get").expect("present").as_slice(),
            b"payload"
        );
        assert_eq!(v.row_count(), Ok(1));
        assert_eq!(v.delete(&id(1)), Ok(true));
        assert_eq!(v.delete(&id(1)), Ok(false));
        assert!(v.get(&id(1)).expect("get").is_none());
    }

    #[test]
    fn outage_fails_every_operation_with_the_vault_named() {
        let v = MemoryVault::new(VaultId::C);
        v.set_available(false);
        let unavailable = ShatterError::VaultUnavailable { vault: VaultId::C };
        assert_eq!(v.put(&id(1), b"x"), Err(unavailable));
        assert_eq!(v.get(&id(1)).err(), Some(unavailable));
        assert_eq!(v.delete(&id(1)).err(), Some(unavailable));
    }
}
