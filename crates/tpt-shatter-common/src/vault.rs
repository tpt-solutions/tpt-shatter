// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::fmt;

use crate::error::ShatterError;

/// Identifies one of the three isolated vaults.
///
/// Each vault is a separate store with its own directory and key (see `FileVault`).
/// Labels are the letters
/// A, B, and C. Each vault also has a domain-separation tag for keyed derivations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VaultId {
    /// Identity fragments.
    A,
    /// Demographic fragments.
    B,
    /// Financial and other sensitive fragments.
    C,
}

impl VaultId {
    /// Every vault, in label order.
    pub const ALL: [Self; 3] = [Self::A, Self::B, Self::C];

    /// The single-letter label for this vault.
    #[must_use]
    pub const fn label(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
        }
    }

    /// Parses a label, accepting upper or lower case.
    pub fn from_label(label: char) -> Result<Self, ShatterError> {
        match label.to_ascii_uppercase() {
            'A' => Ok(Self::A),
            'B' => Ok(Self::B),
            'C' => Ok(Self::C),
            _ => Err(ShatterError::UnknownVault),
        }
    }

    /// Domain-separation tag used when deriving keyed values for this vault.
    #[must_use]
    pub const fn domain_tag(self) -> &'static str {
        match self {
            Self::A => "tpt-shatter/vault-a/v1",
            Self::B => "tpt-shatter/vault-b/v1",
            Self::C => "tpt-shatter/vault-c/v1",
        }
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vault-{}", self.label().to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_round_trip() {
        for v in VaultId::ALL {
            assert_eq!(VaultId::from_label(v.label()), Ok(v));
        }
        assert_eq!(VaultId::from_label('b'), Ok(VaultId::B));
        assert_eq!(VaultId::from_label('D'), Err(ShatterError::UnknownVault));
    }

    #[test]
    fn domain_tags_are_distinct() {
        let tags: std::collections::BTreeSet<_> =
            VaultId::ALL.iter().map(|v| v.domain_tag()).collect();
        assert_eq!(tags.len(), VaultId::ALL.len());
    }

    #[test]
    fn display_names_the_vault() {
        assert_eq!(VaultId::C.to_string(), "vault-c");
    }
}
