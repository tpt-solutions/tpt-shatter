// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::BTreeMap;
use std::thread;

use tpt_shatter_common::{FragmentId, Record, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_vault_client::{Router, derive_fragment_id, encode_fields};
use zeroize::Zeroizing;

/// Outcome of a successful [`Shredder::shred`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShredReport {
    /// Fragments written. Always one per vault.
    pub fragments_written: usize,
}

/// One planned write: which vault, which ID, and the encoded body.
struct Planned {
    vault: VaultId,
    id: FragmentId,
    body: Zeroizing<Vec<u8>>,
}

/// Splits records into per-vault fragments and writes them.
///
/// The shredder holds no mapping table. Fragment IDs are re-derived from the shard
/// key, so the assembler can find them again.
pub struct Shredder<'a> {
    schema: &'a ShatterSchema,
    router: &'a Router,
    derivation_key: Zeroizing<[u8; 32]>,
}

impl<'a> Shredder<'a> {
    /// Creates a shredder. `derivation_key` is held in RAM and zeroed on drop.
    #[must_use]
    pub fn new(schema: &'a ShatterSchema, router: &'a Router, derivation_key: [u8; 32]) -> Self {
        Self {
            schema,
            router,
            derivation_key: Zeroizing::new(derivation_key),
        }
    }

    /// Shreds `record` under `shard`.
    ///
    /// Every field must appear in the schema, otherwise nothing is written and
    /// [`ShatterError::InvalidSchema`] is returned. Each vault receives exactly one
    /// fragment, even if it holds no fields, so reassembly can detect a missing vault.
    ///
    /// Writes run in parallel. If any vault fails, fragments already written are
    /// deleted (saga compensation) and the original error is returned. A retry is safe,
    /// because IDs are deterministic and puts are idempotent. A compensating delete that
    /// itself fails leaves an orphan, which the reaper (not yet implemented) must clean up.
    ///
    /// Dropping `record` zeroes its field values.
    pub fn shred(&self, shard: &ShardKey, record: Record) -> Result<ShredReport, ShatterError> {
        let plan = self.plan(shard, &record)?;
        drop(record);
        self.dispatch(plan)
    }

    fn plan(&self, shard: &ShardKey, record: &Record) -> Result<Vec<Planned>, ShatterError> {
        let mut by_vault: BTreeMap<VaultId, Vec<(&str, &str)>> =
            VaultId::ALL.iter().map(|v| (*v, Vec::new())).collect();
        for name in record.field_names() {
            let vault = self
                .schema
                .vault_for(name)
                .ok_or(ShatterError::InvalidSchema)?;
            let value = record.get(name).ok_or(ShatterError::Internal)?;
            by_vault.entry(vault).or_default().push((name, value));
        }

        let mut plan = Vec::with_capacity(VaultId::ALL.len());
        for vault in VaultId::ALL {
            let fields = by_vault.remove(&vault).unwrap_or_default();
            plan.push(Planned {
                vault,
                id: derive_fragment_id(&self.derivation_key[..], shard, vault)?,
                body: encode_fields(fields)?,
            });
        }
        Ok(plan)
    }

    fn dispatch(&self, plan: Vec<Planned>) -> Result<ShredReport, ShatterError> {
        let router = self.router;
        let outcomes: Vec<(VaultId, Result<(), ShatterError>)> = thread::scope(|scope| {
            let handles: Vec<_> = plan
                .iter()
                .map(|p| {
                    (
                        p.vault,
                        scope.spawn(move || router.put(p.vault, &p.id, &p.body)),
                    )
                })
                .collect();
            handles
                .into_iter()
                .map(|(vault, handle)| {
                    (vault, handle.join().unwrap_or(Err(ShatterError::Internal)))
                })
                .collect()
        });

        let mut first_error = None;
        let mut written = Vec::new();
        for (vault, outcome) in outcomes {
            match outcome {
                Ok(()) => written.push(vault),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }

        if let Some(cause) = first_error {
            // Saga compensation. Failures here are ignored on purpose: the cause is
            // what the caller needs, and any orphan is for the reaper to clean up.
            for p in plan.iter().filter(|p| written.contains(&p.vault)) {
                let _ = router.delete(p.vault, &p.id);
            }
            return Err(cause);
        }
        Ok(ShredReport {
            fragments_written: written.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erase::erase;
    use std::sync::Arc;
    use tpt_shatter_common::SHARD_KEY_LEN;
    use tpt_shatter_vault_client::{BreakerConfig, Guarded, MemoryVault, system_clock};

    const KEY: [u8; 32] = [0x77; 32];

    struct Fixture {
        schema: ShatterSchema,
        router: Router,
        vaults: Vec<Arc<MemoryVault>>,
    }

    fn fixture() -> Fixture {
        let schema = ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("schema");
        let vaults: Vec<Arc<MemoryVault>> = VaultId::ALL
            .iter()
            .map(|v| Arc::new(MemoryVault::new(*v)))
            .collect();
        let guards = vaults
            .iter()
            .map(|v| {
                Guarded::new(
                    Box::new(Arc::clone(v)),
                    BreakerConfig {
                        attempts: 1,
                        ..BreakerConfig::default()
                    },
                    system_clock(),
                )
            })
            .collect();
        let router = Router::new(guards).expect("router");
        Fixture {
            schema,
            router,
            vaults,
        }
    }

    fn record() -> Record {
        let mut r = Record::new();
        r.insert("name", "A. Example");
        r.insert("birth_year", "1990");
        r.insert("card_number", "4111111111111111");
        r
    }

    fn shard() -> ShardKey {
        ShardKey::from_bytes([3; SHARD_KEY_LEN])
    }

    fn rows(f: &Fixture) -> Vec<usize> {
        f.vaults
            .iter()
            .map(|v| v.row_count().expect("count"))
            .collect()
    }

    #[test]
    fn writes_one_fragment_per_vault() {
        let f = fixture();
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        let report = shredder.shred(&shard(), record()).expect("shred");
        assert_eq!(report.fragments_written, 3);
        assert_eq!(rows(&f), [1, 1, 1]);
    }

    #[test]
    fn rejects_fields_outside_the_schema_before_writing() {
        let f = fixture();
        let mut r = record();
        r.insert("shoe_size", "9");
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        assert_eq!(
            shredder.shred(&shard(), r),
            Err(ShatterError::InvalidSchema)
        );
        assert_eq!(rows(&f), [0, 0, 0]);
    }

    #[test]
    fn partial_failure_is_compensated() {
        let f = fixture();
        f.vaults[1].set_available(false);
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        assert_eq!(
            shredder.shred(&shard(), record()),
            Err(ShatterError::VaultUnavailable { vault: VaultId::B })
        );
        // Vaults A and C were written, then removed again, so no orphan remains.
        assert_eq!(rows(&f), [0, 0, 0]);
    }

    #[test]
    fn retry_after_recovery_succeeds_and_is_idempotent() {
        let f = fixture();
        f.vaults[2].set_available(false);
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        assert!(shredder.shred(&shard(), record()).is_err());
        f.vaults[2].set_available(true);
        shredder.shred(&shard(), record()).expect("retry");
        shredder.shred(&shard(), record()).expect("repeat");
        assert_eq!(rows(&f), [1, 1, 1]);
    }

    #[test]
    fn erase_removes_every_fragment_and_is_idempotent() {
        let f = fixture();
        Shredder::new(&f.schema, &f.router, KEY)
            .shred(&shard(), record())
            .expect("shred");
        let first = erase(&f.router, &KEY, &shard()).expect("erase");
        assert_eq!(first.rows_removed, 3);
        assert!(first.verified);
        let second = erase(&f.router, &KEY, &shard()).expect("erase again");
        assert_eq!(second.rows_removed, 0);
        assert!(second.verified);
        assert_eq!(rows(&f), [0, 0, 0]);
    }
}
