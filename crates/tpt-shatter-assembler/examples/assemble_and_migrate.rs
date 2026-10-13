// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Reconstructs a record from its three fragments, shows the deadline variant, then
//! re-shatters the shard under a new schema version without ever holding it on disk.
//!
//! Run with: `cargo run -p tpt-shatter-assembler --example assemble_and_migrate`

use std::sync::Arc;
use std::time::Duration;

use tpt_shatter_assembler::{Assembler, assemble_with_deadline, migrate_shard};
use tpt_shatter_common::{Record, SHARD_KEY_LEN, ShardKey, ShatterSchema, VaultId};
use tpt_shatter_shredder::Shredder;
use tpt_shatter_vault_client::{BreakerConfig, Guarded, MemoryVault, Router, system_clock};

const DERIVATION_KEY: [u8; 32] = [0xA1; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Version 1 puts the card number in vault C.
    let v1 = ShatterSchema::new(
        1,
        [
            ("name", VaultId::A),
            ("birth_year", VaultId::B),
            ("card_number", VaultId::C),
        ],
    )?;
    // Version 2 moves the card number to vault A. Migration does this without losing data.
    let v2 = ShatterSchema::new(
        2,
        [
            ("name", VaultId::A),
            ("birth_year", VaultId::B),
            ("card_number", VaultId::A),
        ],
    )?;

    let router = Arc::new(Router::new(
        VaultId::ALL
            .into_iter()
            .map(|v| {
                Guarded::new(
                    Box::new(MemoryVault::new(v)),
                    BreakerConfig::default(),
                    system_clock(),
                )
            })
            .collect(),
    )?);

    let shard = ShardKey::from_bytes([0x20; SHARD_KEY_LEN]);
    let mut record = Record::new();
    record.insert("name", "Synthetic Person");
    record.insert("birth_year", "1994");
    record.insert("card_number", "4000000000000002");
    Shredder::new(&v1, &router, DERIVATION_KEY).shred(&shard, record)?;

    // 1. Assemble. This fetches all three fragments in parallel and rebuilds the record in
    //    memory. If any fragment is missing or malformed, the call fails. It never returns a
    //    partial record.
    let rebuilt = Assembler::new(&v1, &router, DERIVATION_KEY).assemble(&shard)?;
    println!("v1 assembled {} fields", rebuilt.len());
    print_fields(&rebuilt);

    // 2. Deadline variant. Use it when a slow vault must not stall a request.
    let bounded = assemble_with_deadline(
        &v1,
        &router,
        &DERIVATION_KEY,
        &shard,
        Duration::from_secs(2),
    )?;
    println!("deadline assembly returned {} fields", bounded.len());

    // 3. Migration. Each fragment is rewritten in place under the new schema. A failed run
    //    leaves data readable, and running it again finishes the job.
    migrate_shard(&v1, &v2, &router, &DERIVATION_KEY, &shard)?;
    let after = Assembler::new(&v2, &router, DERIVATION_KEY).assemble(&shard)?;
    println!("v2 assembled {} fields", after.len());
    assert_eq!(after.get("card_number"), rebuilt.get("card_number"));
    println!("card number survives migration unchanged");

    Ok(())
}

/// Prints field names only. Values are sensitive, so this example never prints them.
fn print_fields(record: &Record) {
    for name in record.field_names() {
        println!("  field: {name}");
    }
}
