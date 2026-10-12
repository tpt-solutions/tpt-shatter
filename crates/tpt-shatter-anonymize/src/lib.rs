// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Pure anonymization primitives for tpt-shatter: range bucketing,
//! salted pseudonymization, Laplace noise, a k-anonymity gate, and display masking.
//!
//! Nothing here performs I/O. The Laplace sampler draws from the thread-local RNG,
//! and every other function is deterministic.

use std::fmt;

use sha2::{Digest, Sha256};
use tpt_shatter_common::ShatterError;

/// A closed integer range `[lo, hi]` produced by [`bucket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    lo: i64,
    hi: i64,
}

impl Bucket {
    /// Inclusive lower bound.
    #[must_use]
    pub const fn lo(&self) -> i64 {
        self.lo
    }

    /// Inclusive upper bound.
    #[must_use]
    pub const fn hi(&self) -> i64 {
        self.hi
    }
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.lo, self.hi)
    }
}

/// Places `value` in a fixed-width range. For example, `width = 10` maps 37 to `30-39`.
///
/// Uses Euclidean division, so negative values bucket correctly.
/// Returns [`ShatterError::InvalidParameter`] if `width` is not positive or the range overflows.
pub fn bucket(value: i64, width: i64) -> Result<Bucket, ShatterError> {
    if width <= 0 {
        return Err(ShatterError::InvalidParameter);
    }
    let lo = value
        .div_euclid(width)
        .checked_mul(width)
        .ok_or(ShatterError::InvalidParameter)?;
    let hi = lo
        .checked_add(width - 1)
        .ok_or(ShatterError::InvalidParameter)?;
    Ok(Bucket { lo, hi })
}

/// Length-prefixed salted SHA-256 of `value`. Returns 32 bytes.
///
/// The salt is a secret provisioned outside this crate. Salt provisioning and
/// rotation are in the Phase 3 checklist. An empty salt is rejected, because
/// without a secret salt low-entropy inputs can be brute-forced.
pub fn pseudonymize(salt: &[u8], value: &[u8]) -> Result<[u8; 32], ShatterError> {
    if salt.is_empty() {
        return Err(ShatterError::InvalidParameter);
    }
    let mut hasher = Sha256::new();
    hasher.update((salt.len() as u64).to_be_bytes());
    hasher.update(salt);
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Maps a uniform sample `u` in `(-0.5, 0.5)` to a Laplace variate with the given scale.
///
/// This is the inverse-CDF transform. It is exposed separately so it can be tested
/// without randomness. Inputs at the boundary are clamped to a finite result.
#[must_use]
pub fn laplace_from_uniform(u: f64, scale: f64) -> f64 {
    let magnitude = (1.0 - 2.0 * u.abs()).max(f64::MIN_POSITIVE);
    -scale * u.signum() * magnitude.ln()
}

/// Adds Laplace noise calibrated for epsilon-differential privacy.
///
/// The scale is `sensitivity / epsilon`. Returns [`ShatterError::InvalidParameter`]
/// unless `sensitivity` and `epsilon` are finite and positive, and `value` is finite.
pub fn add_noise(value: f64, sensitivity: f64, epsilon: f64) -> Result<f64, ShatterError> {
    let valid = value.is_finite()
        && sensitivity.is_finite()
        && sensitivity > 0.0
        && epsilon.is_finite()
        && epsilon > 0.0;
    if !valid {
        return Err(ShatterError::InvalidParameter);
    }
    let scale = sensitivity / epsilon;
    // Resample on the (vanishingly rare) draw that lands exactly on the boundary.
    let u = loop {
        let u = rand::random::<f64>() - 0.5;
        if u.abs() < 0.5 {
            break u;
        }
    };
    Ok(value + laplace_from_uniform(u, scale))
}

/// Gate that refuses to emit when any cohort is smaller than `k`.
///
/// Returns [`ShatterError::KAnonymityViolation`] if any cohort size is below `k`.
/// An empty slice passes. Returns [`ShatterError::InvalidParameter`] if `k` is zero.
pub fn check_k_anonymity(cohort_sizes: &[usize], k: usize) -> Result<(), ShatterError> {
    if k == 0 {
        return Err(ShatterError::InvalidParameter);
    }
    if cohort_sizes.iter().any(|&size| size < k) {
        return Err(ShatterError::KAnonymityViolation);
    }
    Ok(())
}

/// Masks all but the last `keep_last` characters with `*` for UI display.
///
/// If `keep_last` is at least the character count, the whole value is masked,
/// because showing the full value would defeat the purpose.
#[must_use]
pub fn mask(value: &str, keep_last: usize) -> String {
    let total = value.chars().count();
    let visible = if keep_last < total { keep_last } else { 0 };
    let masked = total - visible;
    let mut out = String::with_capacity(value.len());
    out.extend(std::iter::repeat_n('*', masked));
    out.extend(value.chars().skip(masked));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn buckets_positive_and_negative_values() {
        let b = bucket(37, 10).expect("valid");
        assert_eq!((b.lo(), b.hi()), (30, 39));
        assert_eq!(b.to_string(), "30-39");
        let n = bucket(-1, 10).expect("valid");
        assert_eq!((n.lo(), n.hi()), (-10, -1));
    }

    #[test]
    fn bucket_boundaries_are_inclusive() {
        assert_eq!(bucket(30, 10).expect("valid").lo(), 30);
        assert_eq!(bucket(39, 10).expect("valid").lo(), 30);
        assert_eq!(bucket(40, 10).expect("valid").lo(), 40);
    }

    #[test]
    fn bucket_rejects_bad_width_and_overflow() {
        assert_eq!(bucket(1, 0), Err(ShatterError::InvalidParameter));
        assert_eq!(bucket(1, -5), Err(ShatterError::InvalidParameter));
        assert_eq!(
            bucket(i64::MAX, i64::MAX),
            Err(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn pseudonym_is_deterministic_and_salt_dependent() {
        let a = pseudonymize(b"salt-1", b"alice").expect("ok");
        let b = pseudonymize(b"salt-1", b"alice").expect("ok");
        let c = pseudonymize(b"salt-2", b"alice").expect("ok");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn pseudonym_rejects_empty_salt() {
        assert_eq!(
            pseudonymize(b"", b"alice"),
            Err(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn pseudonym_separates_salt_from_value() {
        // Without length prefixing, ("ab", "c") and ("a", "bc") would collide.
        let x = pseudonymize(b"ab", b"c").expect("ok");
        let y = pseudonymize(b"a", b"bc").expect("ok");
        assert_ne!(x, y);
    }

    #[test]
    fn laplace_transform_is_centered_and_symmetric() {
        assert_eq!(laplace_from_uniform(0.0, 2.0), 0.0);
        let pos = laplace_from_uniform(0.25, 1.0);
        let neg = laplace_from_uniform(-0.25, 1.0);
        assert!(pos > 0.0 && neg < 0.0);
        assert!((pos + neg).abs() < 1e-12);
        // At u = 0.25 the transform is -ln(0.5) = ln 2.
        assert!((pos - std::f64::consts::LN_2).abs() < 1e-12);
    }

    #[test]
    fn laplace_clamps_boundary_samples() {
        assert!(laplace_from_uniform(0.5, 1.0).is_finite());
        assert!(laplace_from_uniform(-0.5, 1.0).is_finite());
    }

    #[test]
    fn noise_rejects_bad_parameters() {
        assert!(add_noise(1.0, 1.0, 0.0).is_err());
        assert!(add_noise(1.0, 1.0, -1.0).is_err());
        assert!(add_noise(1.0, 0.0, 1.0).is_err());
        assert!(add_noise(f64::NAN, 1.0, 1.0).is_err());
        assert!(add_noise(1.0, f64::INFINITY, 1.0).is_err());
    }

    #[test]
    fn noise_distribution_matches_laplace_scale() {
        // For Laplace(b): mean 0 and E|X| = b. Here b = sensitivity / epsilon = 1.
        const N: usize = 200_000;
        let mut sum = 0.0;
        let mut abs_sum = 0.0;
        for _ in 0..N {
            let x = add_noise(0.0, 1.0, 1.0).expect("valid");
            sum += x;
            abs_sum += x.abs();
        }
        let mean = sum / N as f64;
        let mean_abs = abs_sum / N as f64;
        assert!(mean.abs() < 0.03, "mean {mean}");
        assert!((mean_abs - 1.0).abs() < 0.03, "mean |x| {mean_abs}");
    }

    #[test]
    fn k_anonymity_gate() {
        assert_eq!(check_k_anonymity(&[5, 7, 10], 5), Ok(()));
        assert_eq!(
            check_k_anonymity(&[5, 4, 10], 5),
            Err(ShatterError::KAnonymityViolation)
        );
        assert_eq!(check_k_anonymity(&[], 5), Ok(()));
        assert_eq!(
            check_k_anonymity(&[9], 0),
            Err(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn mask_keeps_only_the_tail() {
        assert_eq!(mask("4111111111111111", 4), "************1111");
        assert_eq!(mask("abc", 4), "***");
        assert_eq!(mask("", 4), "");
        assert_eq!(mask("héllo", 2), "***lo");
    }

    proptest! {
        #[test]
        fn bucket_contains_value_and_has_width(value in -1_000_000i64..1_000_000, width in 1i64..10_000) {
            let b = bucket(value, width).expect("valid");
            prop_assert!(b.lo() <= value && value <= b.hi());
            prop_assert_eq!(b.hi() - b.lo() + 1, width);
            prop_assert_eq!(b.lo().rem_euclid(width), 0);
        }

        #[test]
        fn pseudonym_is_deterministic(
            salt in proptest::collection::vec(any::<u8>(), 1..32),
            value in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assert_eq!(
                pseudonymize(&salt, &value).expect("ok"),
                pseudonymize(&salt, &value).expect("ok")
            );
        }

        #[test]
        fn mask_never_reveals_more_than_the_tail(value in "[a-zA-Z0-9]{0,40}", keep in 0usize..50) {
            let out = mask(&value, keep);
            prop_assert_eq!(out.chars().count(), value.chars().count());
            let visible = out.chars().filter(|c| *c != '*').count();
            prop_assert!(visible <= keep);
            if keep >= value.chars().count() {
                prop_assert!(out.chars().all(|c| c == '*'));
            }
        }
    }
}
