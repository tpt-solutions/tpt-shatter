// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::fmt;

use zeroize::Zeroizing;

use crate::vault::VaultId;

/// One fragment's bytes, bound to the vault it belongs to.
///
/// The bytes are zeroed on drop. The type has no `Clone`, and its `Debug`
/// output shows the vault but never the contents.
pub struct FragmentPayload {
    vault: VaultId,
    bytes: Zeroizing<Vec<u8>>,
}

impl FragmentPayload {
    /// Creates a payload for `vault`, taking ownership of `bytes`.
    #[must_use]
    pub fn new(vault: VaultId, bytes: Vec<u8>) -> Self {
        Self {
            vault,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// The vault this fragment is stored in.
    #[must_use]
    pub const fn vault(&self) -> VaultId {
        self.vault
    }

    /// The fragment bytes. Callers must not log them.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for FragmentPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FragmentPayload")
            .field("vault", &self.vault)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_vault_but_not_bytes() {
        let p = FragmentPayload::new(VaultId::B, b"secret-fragment".to_vec());
        let shown = format!("{p:?}");
        assert!(shown.contains("B"));
        assert!(!shown.contains("secret"));
        assert_eq!(p.bytes(), b"secret-fragment");
        assert_eq!(p.vault(), VaultId::B);
    }
}
