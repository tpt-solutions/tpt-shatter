// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::fmt;

use crate::error::ShatterError;
use crate::shard_key::ShardKey;

/// Default time-to-live for a capability token, in seconds.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 60;

/// Length of the caller tag a token carries. The tag is the first 16 bytes of the caller's
/// name digest, so it is not a secret and does not identify anyone beyond the name.
pub const CALLER_TAG_LEN: usize = 16;

/// An action a token may authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Read a record.
    Read,
    /// Write a record.
    Write,
    /// Delete a record (GDPR erasure).
    Delete,
}

impl Scope {
    const fn bit(self) -> u32 {
        match self {
            Self::Read => 1 << 0,
            Self::Write => 1 << 1,
            Self::Delete => 1 << 2,
        }
    }
}

/// A set of [`Scope`]s granted by a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scopes(u32);

impl Scopes {
    /// The empty set.
    pub const NONE: Self = Self(0);

    /// Builds a set from a list of scopes.
    #[must_use]
    pub fn from_scopes(scopes: &[Scope]) -> Self {
        Self(scopes.iter().fold(0, |acc, s| acc | s.bit()))
    }

    /// Whether this set grants `scope`.
    #[must_use]
    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// The raw bit mask, for encoding into a token.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Decodes a bit mask. Bits that do not name a known [`Scope`] are dropped.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & (Scope::Read.bit() | Scope::Write.bit() | Scope::Delete.bit()))
    }
}

/// A parsed capability token.
///
/// This type holds the claims only. Signature verification and encoding are
/// Phase 4. The shard key is zeroed on drop, and `Debug` redacts it.
pub struct CapabilityToken {
    id: [u8; 32],
    scopes: Scopes,
    issued_at: u64,
    expires_at: u64,
    caller: [u8; CALLER_TAG_LEN],
    shard_key: ShardKey,
}

impl CapabilityToken {
    /// Builds a token from its claims. `ttl_secs` sets the expiry from `issued_at`.
    #[must_use]
    pub fn new(
        id: [u8; 32],
        scopes: Scopes,
        issued_at: u64,
        ttl_secs: u64,
        caller: [u8; CALLER_TAG_LEN],
        shard_key: ShardKey,
    ) -> Self {
        Self {
            id,
            scopes,
            issued_at,
            expires_at: issued_at.saturating_add(ttl_secs),
            caller,
            shard_key,
        }
    }

    /// The token's unique identifier. Logs should record a hash of it, never the value.
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Expiry time in Unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The caller tag the token was issued under. All zeros means the token was issued
    /// without a caller.
    #[must_use]
    pub const fn caller(&self) -> &[u8; CALLER_TAG_LEN] {
        &self.caller
    }

    /// The shard this token is bound to.
    #[must_use]
    pub const fn shard_key(&self) -> &ShardKey {
        &self.shard_key
    }

    /// Checks that the token is live at `now` (Unix seconds).
    ///
    /// Returns [`ShatterError::TokenExpired`] at or after `expires_at`, and
    /// [`ShatterError::InvalidToken`] if `now` is before `issued_at`. Clock-skew
    /// tolerance is Phase 4.
    pub const fn check_live(&self, now: u64) -> Result<(), ShatterError> {
        if now < self.issued_at {
            return Err(ShatterError::InvalidToken);
        }
        if now >= self.expires_at {
            return Err(ShatterError::TokenExpired);
        }
        Ok(())
    }

    /// Checks that the token grants `scope`.
    pub const fn check_scope(&self, scope: Scope) -> Result<(), ShatterError> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(ShatterError::Unauthorized)
        }
    }
}

impl fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityToken")
            .field("scopes", &self.scopes)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("shard_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(issued_at: u64) -> CapabilityToken {
        CapabilityToken::new(
            [9; 32],
            Scopes::from_scopes(&[Scope::Read]),
            issued_at,
            DEFAULT_TOKEN_TTL_SECS,
            [0; CALLER_TAG_LEN],
            ShardKey::from_bytes([3; 32]),
        )
    }

    #[test]
    fn live_within_ttl_and_expired_after() {
        let t = token(1_000);
        assert_eq!(t.expires_at(), 1_060);
        assert!(t.check_live(1_000).is_ok());
        assert!(t.check_live(1_059).is_ok());
        assert_eq!(t.check_live(1_060), Err(ShatterError::TokenExpired));
    }

    #[test]
    fn token_from_the_future_is_invalid() {
        assert_eq!(
            token(1_000).check_live(999),
            Err(ShatterError::InvalidToken)
        );
    }

    #[test]
    fn scope_checks() {
        let t = token(0);
        assert!(t.check_scope(Scope::Read).is_ok());
        assert_eq!(t.check_scope(Scope::Write), Err(ShatterError::Unauthorized));
        assert_eq!(
            t.check_scope(Scope::Delete),
            Err(ShatterError::Unauthorized)
        );
    }

    #[test]
    fn scopes_combine_and_report_bits() {
        let s = Scopes::from_scopes(&[Scope::Read, Scope::Delete]);
        assert!(s.contains(Scope::Read));
        assert!(!s.contains(Scope::Write));
        assert_eq!(s.bits(), 0b101);
        assert_eq!(Scopes::NONE.bits(), 0);
    }

    #[test]
    fn debug_redacts_shard_key() {
        let shown = format!("{:?}", token(0));
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("ShardKey("));
    }

    #[test]
    fn expiry_saturates_instead_of_overflowing() {
        let t = CapabilityToken::new(
            [0; 32],
            Scopes::NONE,
            u64::MAX - 1,
            DEFAULT_TOKEN_TTL_SECS,
            [0; CALLER_TAG_LEN],
            ShardKey::from_bytes([0; 32]),
        );
        assert_eq!(t.expires_at(), u64::MAX);
    }
}
