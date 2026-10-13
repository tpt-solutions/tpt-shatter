// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Loads a schema from JSON, builds a record and a shard key, and writes a keyed
//! audit chain that is then verified and summarized.
//!
//! Run with: `cargo run -p tpt-shatter-common --example schema_and_audit`

use tpt_shatter_common::{
    AuditAction, AuditChain, AuditEvent, FragmentId, Record, ShardKey, ShatterSchema, VaultId,
    report, verify_chain,
};

/// A schema maps every field to exactly one vault. Each vault later holds only its own fields.
const SCHEMA_JSON: &str = r#"{
    "version": 1,
    "fields": {
        "name": "A",
        "birth_year": "B",
        "card_number": "C"
    }
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Schema: parsed and validated. Unknown vault labels or a zero version are rejected.
    let schema = ShatterSchema::from_json_str(SCHEMA_JSON)?;
    println!("schema v{}", schema.version());
    for vault in VaultId::ALL {
        let fields: Vec<&str> = schema.fields_for(vault).collect();
        println!("  vault {vault}: {fields:?}");
    }

    // 2. Record: a plain field map. Field values are sensitive; keep them out of logs.
    let mut record = Record::new();
    record.insert("name", "Synthetic Person");
    record.insert("birth_year", "1994");
    record.insert("card_number", "4000000000000002");
    println!("record has {} fields", record.len());
    for name in record.field_names() {
        // Print the field names only. Never print values in real code.
        println!("  field: {name}");
    }

    // 3. Shard key: 32 random bytes that name one record. Keep it secret.
    //    Here it is fixed so the example is repeatable. Real keys come from a CSPRNG.
    let shard = ShardKey::from_bytes([0x42; 32]);
    println!("shard key length: {} bytes", shard.as_bytes().len());

    // 4. Fragment IDs are opaque 32-byte values. They round-trip through hex.
    let id = FragmentId::from_bytes([0xAB; 32]);
    let parsed = FragmentId::from_hex(&hex(id.as_bytes()))?;
    assert!(id.ct_eq(&parsed));
    println!("fragment id round-trips through hex");

    // 5. Audit chain: each event's MAC covers the previous MAC, so editing or dropping
    //    an entry breaks verification. The chain key is a secret.
    let audit_key = [0x77; 32];
    let mut chain = AuditChain::new(audit_key);
    let token_digest = [0x01; 32];
    let shard_digest = [0x02; 32];
    let events = [
        (AuditAction::Ingest, Some(VaultId::A), 1_700_000_000),
        (AuditAction::Read, Some(VaultId::B), 1_700_000_060),
        (AuditAction::Erasure, None, 1_700_000_120),
    ];
    let mut records = Vec::new();
    for (action, vault, at) in events {
        records.push(chain.append(AuditEvent {
            action,
            token_digest,
            shard_digest,
            vault,
            caller: None,
            at,
        })?);
    }

    // 6. Verify the whole chain, then produce a summary suitable for export.
    verify_chain(audit_key, &records)?;
    let summary = report(audit_key, &records)?;
    println!("audit records: {}", summary.records);
    println!("{}", summary.to_json());

    // 7. A wrong key fails verification. So does any tampered entry.
    let wrong_key = [0x78; 32];
    assert!(verify_chain(wrong_key, &records).is_err());
    println!("verification with the wrong key fails, as expected");

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
