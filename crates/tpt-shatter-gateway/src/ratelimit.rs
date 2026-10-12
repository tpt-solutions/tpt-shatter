// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::HashMap;

use tpt_shatter_common::ShatterError;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

/// Per-key token bucket. The key is a digest, never the raw token or address.
///
/// Each key holds up to `capacity` requests and refills `refill_per_sec` per second.
/// The table is capped at `max_keys`. When it is full, idle buckets are pruned first,
/// and if that frees nothing the request is refused (fail closed).
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    max_keys: usize,
    buckets: HashMap<[u8; 32], Bucket>,
}

impl RateLimiter {
    /// Creates a limiter. All parameters must be positive.
    pub fn new(capacity: u32, refill_per_sec: u32, max_keys: usize) -> Result<Self, ShatterError> {
        if capacity == 0 || refill_per_sec == 0 || max_keys == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self {
            capacity: f64::from(capacity),
            refill_per_sec: f64::from(refill_per_sec),
            max_keys,
            buckets: HashMap::new(),
        })
    }

    /// Spends one token for `key` at `now_ms`, or returns [`ShatterError::RateLimited`].
    pub fn check(&mut self, key: [u8; 32], now_ms: u64) -> Result<(), ShatterError> {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_keys {
            self.prune(now_ms);
            if self.buckets.len() >= self.max_keys {
                return Err(ShatterError::RateLimited);
            }
        }
        let capacity = self.capacity;
        let refill = self.refill_per_sec;
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens: capacity,
            last_ms: now_ms,
        });
        let elapsed_secs = now_ms.saturating_sub(bucket.last_ms) as f64 / 1000.0;
        bucket.tokens = (bucket.tokens + elapsed_secs * refill).min(capacity);
        bucket.last_ms = now_ms;
        if bucket.tokens < 1.0 {
            return Err(ShatterError::RateLimited);
        }
        bucket.tokens -= 1.0;
        Ok(())
    }

    /// Drops buckets that have refilled to capacity, since they carry no state.
    fn prune(&mut self, now_ms: u64) {
        let capacity = self.capacity;
        let refill = self.refill_per_sec;
        self.buckets.retain(|_, b| {
            let elapsed_secs = now_ms.saturating_sub(b.last_ms) as f64 / 1000.0;
            b.tokens + elapsed_secs * refill < capacity
        });
    }

    /// Number of tracked keys.
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];

    #[test]
    fn allows_a_burst_then_refuses() {
        let mut rl = RateLimiter::new(3, 1, 10).expect("limiter");
        for _ in 0..3 {
            assert!(rl.check(A, 0).is_ok());
        }
        assert_eq!(rl.check(A, 0), Err(ShatterError::RateLimited));
    }

    #[test]
    fn refills_over_time() {
        let mut rl = RateLimiter::new(1, 1, 10).expect("limiter");
        assert!(rl.check(A, 0).is_ok());
        assert_eq!(rl.check(A, 500), Err(ShatterError::RateLimited));
        assert!(rl.check(A, 1_000).is_ok());
    }

    #[test]
    fn keys_are_independent() {
        let mut rl = RateLimiter::new(1, 1, 10).expect("limiter");
        assert!(rl.check(A, 0).is_ok());
        assert!(rl.check(B, 0).is_ok());
    }

    #[test]
    fn full_table_fails_closed_for_new_keys() {
        let mut rl = RateLimiter::new(1, 1, 1).expect("limiter");
        assert!(rl.check(A, 0).is_ok());
        // A is still spent at t=0, so it is not pruned, and B has nowhere to go.
        assert_eq!(rl.check(B, 0), Err(ShatterError::RateLimited));
        assert_eq!(rl.tracked_keys(), 1);
    }

    #[test]
    fn idle_buckets_are_pruned_to_make_room() {
        let mut rl = RateLimiter::new(1, 1, 1).expect("limiter");
        assert!(rl.check(A, 0).is_ok());
        assert!(rl.check(B, 10_000).is_ok());
        assert_eq!(rl.tracked_keys(), 1);
    }

    #[test]
    fn rejects_zero_parameters() {
        assert!(RateLimiter::new(0, 1, 1).is_err());
        assert!(RateLimiter::new(1, 0, 1).is_err());
        assert!(RateLimiter::new(1, 1, 0).is_err());
    }
}
