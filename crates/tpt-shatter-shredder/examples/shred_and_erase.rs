// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Splits a record into one fragment per vault, shows where each piece lands, then erases
//! every fragment for the shard. Uses in-memory vaults and synthetic data only.
//!
//! Run with: `cargo run -p tpt-shatter-shredder --example shred_and_erase`

use std::sync::Arc;

use tpt_shatter_common::{Record, SHARD_KEY_LEN, ShardKey, ShatterSchema, VaultId};
use tpt_shatter_shredder::{Shredder, erase};
use tpt_shatter_vault_client::{BreakerConfig, Guarded, MemoryVault, Router, system_clock};

const DERIVATION_KEY: [u8; 32] = [0xA1; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The schema decides which vault holds which field. Each field lives in exactly one vault.
    let schema = ShatterSchema::new(
        1,
        [
            ("name", VaultId::A),
            ("birth_year", VaultId::B),
            ("card_number", VaultId::C),
        ],
    )?;

    // Keep a handle to each vault so we can count rows. The router owns the guarded copies.
    let vaults: Vec<Arc<MemoryVault>> = VaultId::ALL
        .into_iter()
        .map(|v| Arc::new(MemoryVault::new(v)))
        .collect();
    let guards = vaults
        .iter()
        .map(|v| {
            Guarded::new(
                Box::new(Arc::clone(v)),
                BreakerConfig::default(),
                system_clock(),
            )
        })
        .collect();
    let router = Router::new(guards)?;

    // A record is a flat map of fields. Real records come from an ingest path.
    let mut record = Record::new();
    record.insert("name", "Synthetic Person");
    record.insert("birth_year", "1994");
    record.insert("card_number", "4000000000000002");

    // Shred: one fragment per vault, written in parallel. A failure partway through is
    // compensated, so no half-written record is left behind.
    let shard = ShardKey::from_bytes([0x10; SHARD_KEY_LEN]);
    let shredder = Shredder::new(&schema, &router, DERIVATION_KEY);
    let report = shredder.shred(&shard, record)?;
    println!("fragments written: {}", report.fragments_written);
    for (vault, store) in VaultId::ALL.into_iter().zip(&vaults) {
        println!("  vault {vault} rows: {:?}", store.row_count());
    }

    // Erase: GDPR-style removal of every fragment for this shard. It uses maintenance
    // access, so the removal is not seen by canary detection.
    let erased = erase(&router, &DERIVATION_KEY, &shard)?;
    println!(
        "rows removed: {}, verified: {}",
        erased.rows_removed, erased.verified
    );
    for (vault, store) in VaultId::ALL.into_iter().zip(&vaults) {
        println!("  vault {vault} rows after erase: {:?}", store.row_count());
    }

    // The reaper retries fragments that could not be deleted earlier. Here nothing is queued.
    let reaped = shredder.reap(5)?;
    println!(
        "orphans removed: {}, still pending: {}",
        reaped.removed, reaped.still_pending
    );

    Ok(())
}
