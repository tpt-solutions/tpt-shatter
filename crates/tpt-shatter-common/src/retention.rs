// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Fragment retention: a maximum age after which fragments must be purged.

use crate::error::ShatterError;

/// A maximum fragment age, in seconds.
///
/// Times are Unix seconds. A fragment stored at `t` expires at `t + max_age_secs`
/// (saturating), and is expired from that instant onward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    max_age_secs: u64,
}

impl RetentionPolicy {
    /// Creates a policy. A zero maximum age is rejected, since it would purge everything at once.
    pub const fn new(max_age_secs: u64) -> Result<Self, ShatterError> {
        if max_age_secs == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self { max_age_secs })
    }

    /// The maximum age in seconds.
    #[must_use]
    pub const fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    /// The instant at which a fragment stored at `stored_at` expires.
    #[must_use]
    pub const fn expires_at(&self, stored_at: u64) -> u64 {
        stored_at.saturating_add(self.max_age_secs)
    }

    /// Whether a fragment stored at `stored_at` is expired at time `now`.
    #[must_use]
    pub const fn is_expired(&self, stored_at: u64, now: u64) -> bool {
        now >= self.expires_at(stored_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_age() {
        assert_eq!(RetentionPolicy::new(0), Err(ShatterError::InvalidParameter));
    }

    #[test]
    fn expires_exactly_at_the_limit() {
        let p = RetentionPolicy::new(100).expect("policy");
        assert_eq!(p.expires_at(1_000), 1_100);
        assert!(!p.is_expired(1_000, 1_099));
        assert!(p.is_expired(1_000, 1_100));
    }

    #[test]
    fn expiry_saturates_instead_of_overflowing() {
        let p = RetentionPolicy::new(u64::MAX).expect("policy");
        assert_eq!(p.expires_at(10), u64::MAX);
        assert!(!p.is_expired(10, u64::MAX - 1));
    }
}
