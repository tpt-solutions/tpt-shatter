// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::fmt;

use crate::error::ShatterError;
use crate::shard_key::decode_hex;

/// Length of a [`FragmentId`] in bytes.
pub const FRAGMENT_ID_LEN: usize = 32;

/// Opaque linking ID for a fragment.
///
/// A `FragmentId` is meant to be derived from a [`ShardKey`](crate::ShardKey)
/// with a keyed one-way hash, so it is not a mapping key. Derivation itself is
/// Phase 6; this type only holds the value. It has no `Display`, a redacted
/// `Debug`, and constant-time equality.
#[derive(Clone)]
pub struct FragmentId([u8; FRAGMENT_ID_LEN]);

impl FragmentId {
    /// Wraps raw identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FRAGMENT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses a hex string of exactly 64 characters.
    pub fn from_hex(hex: &str) -> Result<Self, ShatterError> {
        decode_hex::<FRAGMENT_ID_LEN>(hex).map(Self)
    }

    /// Returns the raw identifier bytes. Callers must not log them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FRAGMENT_ID_LEN] {
        &self.0
    }

    /// Compares two identifiers in constant time.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl PartialEq for FragmentId {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for FragmentId {}

impl fmt::Debug for FragmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FragmentId(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let id = FragmentId::from_bytes([0xAB; FRAGMENT_ID_LEN]);
        assert_eq!(format!("{id:?}"), "FragmentId(<redacted>)");
    }

    #[test]
    fn equality_tracks_bytes() {
        let a = FragmentId::from_bytes([1; FRAGMENT_ID_LEN]);
        let b = FragmentId::from_bytes([1; FRAGMENT_ID_LEN]);
        let mut other = [1; FRAGMENT_ID_LEN];
        other[FRAGMENT_ID_LEN - 1] = 2;
        let c = FragmentId::from_bytes(other);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let id = FragmentId::from_hex(&"ab".repeat(FRAGMENT_ID_LEN)).expect("valid hex");
        assert_eq!(id.as_bytes(), &[0xAB; FRAGMENT_ID_LEN]);
        assert_eq!(
            FragmentId::from_hex("abc"),
            Err(ShatterError::InvalidShardKey)
        );
        assert_eq!(
            FragmentId::from_hex(&"zz".repeat(FRAGMENT_ID_LEN)),
            Err(ShatterError::InvalidShardKey)
        );
    }
}
