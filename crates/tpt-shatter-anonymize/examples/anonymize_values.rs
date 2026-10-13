// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Walks through each anonymization primitive on a small, made-up dataset: bucketing,
//! salted pseudonyms, Laplace noise, the k-anonymity gate, and display masking.
//!
//! Run with: `cargo run -p tpt-shatter-anonymize --example anonymize_values`

use tpt_shatter_anonymize::{add_noise, bucket, check_k_anonymity, mask, pseudonymize};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bucketing turns an exact value into a range. Width 10 maps 1994 to 1990-1999.
    let year = bucket(1994, 10)?;
    println!(
        "birth year 1994 -> {year} (lo={}, hi={})",
        year.lo(),
        year.hi()
    );

    // Negative values bucket correctly, because division is Euclidean.
    println!("-1 with width 10 -> {}", bucket(-1, 10)?);

    // Pseudonyms are salted SHA-256 digests. The same input and salt always give the same
    // output, so records can still be joined. The salt must be a real secret: an empty salt
    // is rejected, because without one a low-entropy name can be brute-forced.
    let salt = b"example-salt-kept-in-a-secret-store";
    let alice_a = pseudonymize(salt, b"alice@example.invalid")?;
    let alice_b = pseudonymize(salt, b"alice@example.invalid")?;
    assert_eq!(alice_a, alice_b);
    let hex: String = alice_a.iter().map(|b| format!("{b:02x}")).collect();
    println!("pseudonym: {}...", &hex[..16]);

    // Laplace noise for differential privacy. The scale is sensitivity / epsilon.
    // Smaller epsilon means more noise and a stronger privacy guarantee.
    let true_count = 42.0;
    let noisy = add_noise(true_count, 1.0, 0.5)?;
    println!("count 42 with epsilon 0.5 -> {noisy:.2} (noisy)");

    // Invalid parameters are errors, not silent defaults.
    assert!(add_noise(true_count, 1.0, 0.0).is_err());

    // k-anonymity gate: refuse to emit if any group of quasi-identifiers is smaller than k.
    // Here the cohort sizes are the number of records sharing each quasi-identifier value.
    let cohorts_ok = [12, 7, 5];
    check_k_anonymity(&cohorts_ok, 5)?;
    println!("cohorts {cohorts_ok:?} pass k=5");

    let cohorts_bad = [12, 3, 5];
    match check_k_anonymity(&cohorts_bad, 5) {
        Ok(()) => println!("unexpected pass"),
        Err(e) => println!("cohorts {cohorts_bad:?} refused: {e}"),
    }

    // Display masking keeps only the last few characters. If keep_last covers the whole
    // value, everything is masked, so a short value can never be shown in full.
    println!("card: {}", mask("4000000000000002", 4));
    println!("short value fully masked: {}", mask("abc", 4));

    Ok(())
}
