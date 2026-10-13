// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Shows the vault layer end to end: wire-format encoding, keyed FragmentIds, a router over
//! three in-memory vaults, and an encrypted on-disk vault with retention.
//!
//! Run with: `cargo run -p tpt-shatter-vault-client --example router_and_file_vault`

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_shatter_common::{RetentionPolicy, SHARD_KEY_LEN, ShardKey, VaultId};
use tpt_shatter_vault_client::{
    BreakerConfig, FileVault, Guarded, MemoryVault, Router, VaultBackend, add_schema_version,
    decode_fields, derive_fragment_id, encode_fields, split_schema_version, system_clock,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Keys are supplied by the caller and should come from a secret store. These are fixed
    // so the example is repeatable.
    let derivation_key = [0xA1; 32];
    let shard = ShardKey::from_bytes([0x10; SHARD_KEY_LEN]);

    // 1. Wire format. Fields are encoded, then prefixed with the schema version so a reader
    //    can tell which schema wrote the bytes.
    let body = encode_fields([("name", "Synthetic Person")])?;
    let framed = add_schema_version(1, &body);
    let (version, rest) = split_schema_version(&framed)?;
    let decoded = decode_fields(rest)?;
    println!(
        "schema version {version}, decoded {} field(s)",
        decoded.len()
    );

    // 2. FragmentIds are keyed. The same shard in two vaults gives two unrelated IDs, so a
    //    vault cannot tell which fragments belong to the same record.
    let id_a = derive_fragment_id(&derivation_key, &shard, VaultId::A)?;
    let id_b = derive_fragment_id(&derivation_key, &shard, VaultId::B)?;
    assert!(!id_a.ct_eq(&id_b));
    println!("vault A and vault B IDs for one shard differ");

    // 3. Router: every call names exactly one vault. There is no call that spans vaults.
    //    Each vault is wrapped in a breaker (`Guarded`) that trips after repeated failures.
    let guards = VaultId::ALL
        .into_iter()
        .map(|vault| {
            Guarded::new(
                Box::new(MemoryVault::new(vault)),
                BreakerConfig::default(),
                system_clock(),
            )
        })
        .collect();
    let router = Router::new(guards)?;

    router.put(VaultId::A, &id_a, &framed)?;
    let stored = router.get(VaultId::A, &id_a)?.ok_or("fragment missing")?;
    println!("read back {} bytes from vault A", stored.len());

    // A missing fragment is `None`, not an error.
    assert!(router.get(VaultId::B, &id_a)?.is_none());
    println!("vault B does not hold vault A's fragment");

    // Each vault reports its breaker state, which the readiness probe uses.
    for status in router.statuses()? {
        println!("vault {}: {:?}", status.vault, status.state);
    }

    // 4. File vault: one encrypted file per fragment, on disk. Each vault has its own key.
    let dir = std::env::temp_dir().join("tpt-shatter-example-file-vault");
    let _ = fs::remove_dir_all(&dir);
    let file_vault = FileVault::open(VaultId::C, &dir, &[0x5A; 32])?;
    file_vault.put(&id_a, &framed)?;
    println!(
        "file vault holds the fragment: {}",
        file_vault.get(&id_a)?.is_some()
    );

    // 5. Retention. A fragment older than the policy is erased. Pass a "now" in the future
    //    to see it happen without waiting.
    let policy = RetentionPolicy::new(3_600)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = file_vault.purge_expired(policy, now + 7_200)?;
    println!("purged {} expired fragment(s)", report.purged);
    println!(
        "fragment still present after purge: {}",
        file_vault.get(&id_a)?.is_some()
    );

    // Clean up the example directory. The fragment was already erased by the purge above.
    // Deleting a single fragment through `delete` overwrites it with zeros first.
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
