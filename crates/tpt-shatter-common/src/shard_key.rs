// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::fmt;

use zeroize::Zeroizing;

use crate::error::ShatterError;

/// Length of a [`ShardKey`] in bytes (256 bits).
pub const SHARD_KEY_LEN: usize = 32;

/// Routing key that identifies a record for reassembly.
///
/// A shard key carries 256 bits of entropy and is zeroed on drop. It has no
/// `Clone`, no `Display`, and a redacted `Debug`. The caller is responsible for
/// supplying high-entropy bytes; generation from a CSPRNG belongs to Phase 4.
pub struct ShardKey(Zeroizing<[u8; SHARD_KEY_LEN]>);

impl ShardKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHARD_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Parses a hex string of exactly 64 characters, in either case.
    pub fn from_hex(hex: &str) -> Result<Self, ShatterError> {
        decode_hex::<SHARD_KEY_LEN>(hex).map(Self::from_bytes)
    }

    /// Returns the raw key bytes. Callers must not log them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARD_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for ShardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShardKey(<redacted>)")
    }
}

/// Decodes a hex string of exactly `2 * N` characters into `N` bytes.
pub(crate) fn decode_hex<const N: usize>(hex: &str) -> Result<[u8; N], ShatterError> {
    let raw = hex.as_bytes();
    if raw.len() != 2 * N {
        return Err(ShatterError::InvalidShardKey);
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, ShatterError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ShatterError::InvalidShardKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let key = ShardKey::from_bytes([7; SHARD_KEY_LEN]);
        assert_eq!(format!("{key:?}"), "ShardKey(<redacted>)");
    }

    #[test]
    fn hex_parses_both_cases() {
        let lower = ShardKey::from_hex(&"0f".repeat(SHARD_KEY_LEN)).expect("lower");
        let upper = ShardKey::from_hex(&"0F".repeat(SHARD_KEY_LEN)).expect("upper");
        assert_eq!(lower.as_bytes(), upper.as_bytes());
        assert_eq!(lower.as_bytes()[0], 0x0F);
    }

    #[test]
    fn hex_rejects_wrong_length_and_non_hex() {
        assert_eq!(
            ShardKey::from_hex("").err(),
            Some(ShatterError::InvalidShardKey)
        );
        assert_eq!(
            ShardKey::from_hex(&"00".repeat(SHARD_KEY_LEN - 1)).err(),
            Some(ShatterError::InvalidShardKey)
        );
        assert_eq!(
            ShardKey::from_hex(&"g0".repeat(SHARD_KEY_LEN)).err(),
            Some(ShatterError::InvalidShardKey)
        );
    }
}
