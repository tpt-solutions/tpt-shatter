// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Applies an anonymization policy to a batch of reconstructed records, emits the result to a
//! durable JSON-lines log, and shows the k-anonymity gate refusing a batch with a small cohort.
//!
//! Run with: `cargo run -p tpt-shatter-emitter --example policy_and_k_anonymity`

use std::fs;

use tpt_shatter_common::Record;
use tpt_shatter_emitter::{Emitter, JsonlSink, MemorySink, Policy, Transform};

fn person(name: &str, birth_year: &str, card: &str) -> Record {
    let mut r = Record::new();
    r.insert("name", name);
    r.insert("birth_year", birth_year);
    r.insert("card_number", card);
    r.insert("internal_notes", "not in the policy, so it is dropped");
    r
}

fn policy(k: usize) -> Result<Policy, Box<dyn std::error::Error>> {
    Ok(Policy::new(
        // The salt makes pseudonyms unguessable. Keep it in a secret store.
        b"example-emitter-salt".to_vec(),
        [
            // Pseudonymize: the value becomes a salted digest, still joinable.
            ("name".to_owned(), Transform::Pseudonymize),
            // Bucket: 1994 becomes a 10-year range.
            ("birth_year".to_owned(), Transform::Bucket { width: 10 }),
            // Mask: only the last four digits remain.
            ("card_number".to_owned(), Transform::Mask { keep_last: 4 }),
        ],
        // Quasi-identifiers are the fields an attacker could combine to re-identify someone.
        // k-anonymity is checked over these.
        vec!["birth_year".to_owned()],
        k,
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Two 1990s births and two 2000s births. With k = 2 every cohort has at least two rows.
    let batch = vec![
        person("Synthetic A", "1994", "4000000000000002"),
        person("Synthetic B", "1996", "4000000000000010"),
        person("Synthetic C", "2003", "4000000000000028"),
        person("Synthetic D", "2008", "4000000000000036"),
    ];

    // 1. Emit to memory. Fields with no rule are dropped, so `internal_notes` never leaves.
    let emitter = Emitter::new(policy(2)?, MemorySink::new());
    let report = emitter.emit(batch)?;
    println!("emitted {} records", report.emitted);
    for event in emitter.sink().events()? {
        println!(
            "  name={} year_range={} card={} notes={:?}",
            event.get("name").unwrap_or("-"),
            event.get("birth_year").unwrap_or("-"),
            event.get("card_number").unwrap_or("-"),
            event.get("internal_notes"),
        );
    }

    // 2. Durable output. The JSON-lines sink appends, so a restart does not lose history.
    let path = std::env::temp_dir().join("tpt-shatter-example-emitted.jsonl");
    let _ = fs::remove_file(&path);
    let file_sink = JsonlSink::open(&path)?;
    let file_emitter = Emitter::new(policy(2)?, file_sink);
    file_emitter.emit(vec![
        person("Synthetic E", "1995", "4000000000000044"),
        person("Synthetic F", "1997", "4000000000000052"),
    ])?;
    let stored = JsonlSink::read_all(&path)?;
    println!("file holds {} event(s) at {}", stored.len(), path.display());
    let _ = fs::remove_file(&path);

    // 3. The gate refuses the whole batch if any cohort is too small. Here one record born in
    //    1982 is alone in its decade, so nothing is emitted at all.
    let small_cohort = vec![
        person("Synthetic F", "1982", "4000000000000051"),
        person("Synthetic G", "1994", "4000000000000069"),
        person("Synthetic H", "1997", "4000000000000077"),
    ];
    match Emitter::new(policy(2)?, MemorySink::new()).emit(small_cohort) {
        Ok(_) => println!("unexpected: batch was emitted"),
        Err(e) => println!("batch refused: {e}"),
    }

    Ok(())
}
