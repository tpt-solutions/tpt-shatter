// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Re-shatters one shard from one schema version to another.
//!
//! Each fragment is overwritten in place, so the old version is retired by the write
//! itself. Every fragment is read under the schema its own version header names, so a
//! shard left half-migrated by an earlier failure still reads correctly, and a re-run
//! finishes it.
//!
//! This does not go through the shredder. Its saga deletes the fragments it wrote when
//! any vault fails. Here that would delete new-version data and lose the shard. A failed
//! migration therefore leaves nothing that needs undoing, and a retry completes it.

use std::collections::BTreeMap;

use tpt_shatter_common::{ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_vault_client::{
    Router, add_schema_version, decode_fields, derive_fragment_id, encode_fields,
    split_schema_version,
};
use zeroize::Zeroizing;

use crate::Assembler;

/// Moves the shard `shard` from the `from` schema to the `to` schema.
///
/// The shard must be complete: every vault must hold a fragment written under `from`
/// or `to`. Every field must have a vault under `to`, or nothing is written. Each vault
/// is then overwritten with its `to` fragment. The result is read back through the
/// assembler under `to` and compared with what was read before the writes.
///
/// A failure part-way leaves some vaults on the new version. The shard stays readable
/// through this function, not through the assembler, until a re-run completes it.
///
/// Returns [`ShatterError::InvalidParameter`] if the two schemas share a version.
pub fn migrate_shard(
    from: &ShatterSchema,
    to: &ShatterSchema,
    router: &Router,
    derivation_key: &[u8; 32],
    shard: &ShardKey,
) -> Result<(), ShatterError> {
    if from.version() == to.version() {
        return Err(ShatterError::InvalidParameter);
    }
    let merged = read_merged(from, to, router, derivation_key, shard)?;

    // Refuse before any write if a field has no vault under the new schema.
    let mut by_vault: BTreeMap<VaultId, Vec<(&str, &str)>> =
        VaultId::ALL.iter().map(|v| (*v, Vec::new())).collect();
    for (name, value) in &merged {
        let vault = to.vault_for(name).ok_or(ShatterError::InvalidSchema)?;
        by_vault
            .entry(vault)
            .or_default()
            .push((name.as_str(), value.as_str()));
    }

    for vault in VaultId::ALL {
        let fields = by_vault.remove(&vault).unwrap_or_default();
        let id = derive_fragment_id(&derivation_key[..], shard, vault)?;
        let body = add_schema_version(to.version(), &encode_fields(fields)?);
        router.put(vault, &id, &body)?;
    }

    // Verify through the assembler, which is the read path the node uses.
    let rebuilt = Assembler::new(to, router, *derivation_key).assemble(shard)?;
    let matches = rebuilt.len() == merged.len()
        && merged
            .iter()
            .all(|(name, value)| rebuilt.get(name) == Some(value.as_str()));
    if matches {
        Ok(())
    } else {
        Err(ShatterError::Reconstruction)
    }
}

/// Reads every fragment of the shard and merges their fields.
///
/// A fragment under `to` is checked against `to`'s vault mapping, and one under `from`
/// against `from`'s. A field present in both a `to` fragment and a `from` fragment takes
/// the `to` value, because a `to` fragment is always written after its field moves.
fn read_merged(
    from: &ShatterSchema,
    to: &ShatterSchema,
    router: &Router,
    derivation_key: &[u8; 32],
    shard: &ShardKey,
) -> Result<BTreeMap<String, Zeroizing<String>>, ShatterError> {
    let mut current = BTreeMap::new();
    let mut older = BTreeMap::new();
    for vault in VaultId::ALL {
        let id = derive_fragment_id(&derivation_key[..], shard, vault)?;
        // Maintenance read: migration must not trip canary detection.
        let body = router
            .get_maintenance(vault, &id)?
            .ok_or(ShatterError::Reconstruction)?;
        let (version, fields) = split_schema_version(&body)?;
        let (schema, target) = if version == to.version() {
            (to, &mut current)
        } else if version == from.version() {
            (from, &mut older)
        } else {
            return Err(ShatterError::Reconstruction);
        };
        for (name, value) in decode_fields(fields)? {
            if schema.vault_for(&name) != Some(vault) || target.insert(name, value).is_some() {
                return Err(ShatterError::Reconstruction);
            }
        }
    }
    for (name, value) in older {
        current.entry(name).or_insert(value);
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tpt_shatter_common::{FragmentId, Record, SHARD_KEY_LEN};
    use tpt_shatter_shredder::Shredder;
    use tpt_shatter_vault_client::{
        BreakerConfig, Guarded, MemoryVault, VaultBackend, system_clock,
    };

    const KEY: [u8; 32] = [0x7D; 32];

    struct Fixture {
        router: Router,
        vaults: Vec<Arc<MemoryVault>>,
    }

    fn v1() -> ShatterSchema {
        ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("v1")
    }

    /// Version 2 moves `birth_year` from vault B into vault A.
    fn v2() -> ShatterSchema {
        ShatterSchema::new(
            2,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::A),
                ("card_number", VaultId::C),
            ],
        )
        .expect("v2")
    }

    /// Passes reads through to a vault, and rejects writes while `fail_writes` is set.
    struct WriteFault {
        inner: Arc<MemoryVault>,
        fail_writes: Arc<AtomicBool>,
    }

    impl VaultBackend for WriteFault {
        fn vault(&self) -> VaultId {
            self.inner.vault()
        }

        fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(ShatterError::VaultUnavailable {
                    vault: self.inner.vault(),
                });
            }
            self.inner.put(id, bytes)
        }

        fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
            self.inner.get(id)
        }

        fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
            self.inner.delete(id)
        }
    }

    fn fixture() -> Fixture {
        fixture_with_write_fault(None).0
    }

    /// Builds the fixture. With a fault flag, vault C rejects writes while it is set.
    fn fixture_with_write_fault(
        fault: Option<Arc<AtomicBool>>,
    ) -> (Fixture, Option<Arc<AtomicBool>>) {
        let vaults: Vec<Arc<MemoryVault>> = VaultId::ALL
            .iter()
            .map(|v| Arc::new(MemoryVault::new(*v)))
            .collect();
        let guards = vaults
            .iter()
            .map(|v| {
                let backend: Box<dyn VaultBackend> = match &fault {
                    Some(flag) if v.vault() == VaultId::C => Box::new(WriteFault {
                        inner: Arc::clone(v),
                        fail_writes: Arc::clone(flag),
                    }),
                    _ => Box::new(Arc::clone(v)),
                };
                Guarded::new(
                    backend,
                    BreakerConfig {
                        attempts: 1,
                        ..BreakerConfig::default()
                    },
                    system_clock(),
                )
            })
            .collect();
        let fixture = Fixture {
            router: Router::new(guards).expect("router"),
            vaults,
        };
        (fixture, fault)
    }

    fn shard() -> ShardKey {
        ShardKey::from_bytes([0x21; SHARD_KEY_LEN])
    }

    fn record() -> Record {
        let mut r = Record::new();
        r.insert("name", "A. Example");
        r.insert("birth_year", "1990");
        r.insert("card_number", "4111111111111111");
        r
    }

    fn shred_v1(f: &Fixture) {
        Shredder::new(&v1(), &f.router, KEY)
            .shred(&shard(), record())
            .expect("shred");
    }

    fn version_in(f: &Fixture, vault: VaultId) -> u32 {
        let id = derive_fragment_id(&KEY, &shard(), vault).expect("id");
        let body = f
            .router
            .get_maintenance(vault, &id)
            .expect("get")
            .expect("present");
        split_schema_version(&body).expect("split").0
    }

    fn assert_reads_as_original(schema: &ShatterSchema, f: &Fixture) {
        let rebuilt = Assembler::new(schema, &f.router, KEY)
            .assemble(&shard())
            .expect("assemble");
        assert_eq!(rebuilt.len(), 3);
        assert_eq!(rebuilt.get("name"), Some("A. Example"));
        assert_eq!(rebuilt.get("birth_year"), Some("1990"));
        assert_eq!(rebuilt.get("card_number"), Some("4111111111111111"));
    }

    #[test]
    fn migrates_a_shard_and_moves_a_field_between_vaults() {
        let f = fixture();
        shred_v1(&f);
        migrate_shard(&v1(), &v2(), &f.router, &KEY, &shard()).expect("migrate");
        assert_reads_as_original(&v2(), &f);
        for vault in VaultId::ALL {
            assert_eq!(version_in(&f, vault), 2);
        }
        // The old schema no longer reads the shard.
        assert_eq!(
            Assembler::new(&v1(), &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn rerunning_a_finished_migration_still_verifies() {
        let f = fixture();
        shred_v1(&f);
        migrate_shard(&v1(), &v2(), &f.router, &KEY, &shard()).expect("first");
        // Every fragment is already on `to`, so this run reads only `to` fragments.
        migrate_shard(&v1(), &v2(), &f.router, &KEY, &shard()).expect("second");
        assert_reads_as_original(&v2(), &f);
    }

    #[test]
    fn an_interrupted_migration_completes_on_rerun_without_losing_data() {
        let fault = Arc::new(AtomicBool::new(false));
        let (f, _) = fixture_with_write_fault(Some(Arc::clone(&fault)));
        shred_v1(&f);
        // Vault C now rejects writes. A and B are already on version 2 when it does.
        fault.store(true, Ordering::SeqCst);
        assert_eq!(
            migrate_shard(&v1(), &v2(), &f.router, &KEY, &shard()),
            Err(ShatterError::VaultUnavailable { vault: VaultId::C })
        );
        assert_eq!(version_in(&f, VaultId::A), 2);
        assert_eq!(version_in(&f, VaultId::C), 1);
        // Nothing was deleted, so C's old fragment is still there.
        assert_eq!(f.vaults[2].row_count(), Ok(1));

        fault.store(false, Ordering::SeqCst);
        migrate_shard(&v1(), &v2(), &f.router, &KEY, &shard()).expect("rerun");
        assert_reads_as_original(&v2(), &f);
    }

    #[test]
    fn a_field_with_no_vault_in_the_new_schema_is_refused_before_any_write() {
        let f = fixture();
        shred_v1(&f);
        let incomplete = ShatterSchema::new(2, [("name", VaultId::A), ("birth_year", VaultId::A)])
            .expect("schema");
        assert_eq!(
            migrate_shard(&v1(), &incomplete, &f.router, &KEY, &shard()),
            Err(ShatterError::InvalidSchema)
        );
        for vault in VaultId::ALL {
            assert_eq!(version_in(&f, vault), 1);
        }
    }

    #[test]
    fn an_incomplete_shard_is_refused_before_any_write() {
        let f = fixture();
        shred_v1(&f);
        let id = derive_fragment_id(&KEY, &shard(), VaultId::B).expect("id");
        f.router
            .delete_maintenance(VaultId::B, &id)
            .expect("delete");
        assert_eq!(
            migrate_shard(&v1(), &v2(), &f.router, &KEY, &shard()),
            Err(ShatterError::Reconstruction)
        );
        assert_eq!(version_in(&f, VaultId::A), 1);
        assert_eq!(version_in(&f, VaultId::C), 1);
    }

    #[test]
    fn a_shard_under_a_third_version_is_refused() {
        let f = fixture();
        shred_v1(&f);
        let v3 = ShatterSchema::new(
            3,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::A),
                ("card_number", VaultId::C),
            ],
        )
        .expect("v3");
        // Migrating from v2 finds v1 fragments, which are neither from nor to.
        assert_eq!(
            migrate_shard(&v2(), &v3, &f.router, &KEY, &shard()),
            Err(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn same_version_is_rejected() {
        let f = fixture();
        assert_eq!(
            migrate_shard(&v1(), &v1(), &f.router, &KEY, &shard()),
            Err(ShatterError::InvalidParameter)
        );
    }
}
