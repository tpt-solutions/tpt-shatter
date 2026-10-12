// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::thread;

use tpt_shatter_common::{FragmentId, Record, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_vault_client::{Router, add_schema_version, derive_fragment_id, encode_fields};
use zeroize::Zeroizing;

use crate::orphans::{Orphan, OrphanLog};

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

/// Outcome of one [`Shredder::reap`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapReport {
    /// Orphans deleted by this pass.
    pub removed: usize,
    /// Orphans that failed this pass and will be retried.
    pub still_pending: usize,
    /// Orphans dropped after reaching `max_attempts`. Each one needs an operator.
    pub abandoned: usize,
}

/// Splits records into per-vault fragments and writes them.
///
/// The shredder holds no mapping table. Fragment IDs are re-derived from the shard
/// key, so the assembler can find them again.
pub struct Shredder<'a> {
    schema: &'a ShatterSchema,
    router: &'a Router,
    derivation_key: Zeroizing<[u8; 32]>,
    orphans: Mutex<Vec<Orphan>>,
    orphan_log: Option<OrphanLog>,
}

impl<'a> Shredder<'a> {
    /// Creates a shredder whose orphan queue lives in RAM only.
    /// `derivation_key` is held in RAM and zeroed on drop.
    #[must_use]
    pub fn new(schema: &'a ShatterSchema, router: &'a Router, derivation_key: [u8; 32]) -> Self {
        Self {
            schema,
            router,
            derivation_key: Zeroizing::new(derivation_key),
            orphans: Mutex::new(Vec::new()),
            orphan_log: None,
        }
    }

    /// Like [`Shredder::new`], but the orphan queue is backed by the file at `path`.
    ///
    /// Orphans left in the file by an earlier run are loaded and will be reaped. New
    /// orphans are written to the file before they are queued, and a reap rewrites it.
    pub fn with_orphan_log(
        schema: &'a ShatterSchema,
        router: &'a Router,
        derivation_key: [u8; 32],
        path: &Path,
    ) -> Result<Self, ShatterError> {
        let (log, loaded) = OrphanLog::open(path)?;
        Ok(Self {
            schema,
            router,
            derivation_key: Zeroizing::new(derivation_key),
            orphans: Mutex::new(loaded),
            orphan_log: Some(log),
        })
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
    /// itself fails queues an orphan, which [`Shredder::reap`] retries.
    ///
    /// Dropping `record` zeroes its field values.
    pub fn shred(&self, shard: &ShardKey, record: Record) -> Result<ShredReport, ShatterError> {
        let plan = self.plan(shard, &record)?;
        drop(record);
        self.dispatch(plan)
    }

    /// Number of orphan fragments waiting for [`Shredder::reap`].
    pub fn pending_orphans(&self) -> Result<usize, ShatterError> {
        Ok(self
            .orphans
            .lock()
            .map_err(|_| ShatterError::Internal)?
            .len())
    }

    /// Retries every queued orphan delete once.
    ///
    /// An orphan that has failed `max_attempts` times in total is dropped and counted
    /// as abandoned, so the queue cannot grow forever. Abandoned orphans need an
    /// operator. The queue lives in RAM, so a restart loses it; see `todo.md`.
    pub fn reap(&self, max_attempts: u32) -> Result<ReapReport, ShatterError> {
        if max_attempts == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        // Take the batch out so the lock is not held during vault calls. Orphans
        // queued meanwhile are merged back below.
        let batch = std::mem::take(&mut *self.orphans.lock().map_err(|_| ShatterError::Internal)?);
        let mut report = ReapReport {
            removed: 0,
            still_pending: 0,
            abandoned: 0,
        };
        let mut keep = Vec::new();
        for mut orphan in batch {
            match self.router.delete(orphan.vault, &orphan.id) {
                Ok(_) => report.removed += 1,
                Err(_) => {
                    orphan.attempts += 1;
                    if orphan.attempts >= max_attempts {
                        report.abandoned += 1;
                    } else {
                        report.still_pending += 1;
                        keep.push(orphan);
                    }
                }
            }
        }
        let mut queue = self.orphans.lock().map_err(|_| ShatterError::Internal)?;
        queue.extend(keep);
        if let Some(log) = &self.orphan_log {
            // Orphans that were removed above may still be in the file if this write
            // fails. A later reap deletes them again, which is harmless.
            log.replace(&queue)?;
        }
        Ok(report)
    }

    /// Queues orphans in RAM and, when a log is configured, on disk.
    ///
    /// The disk write happens first. If it fails, the orphans are still queued in RAM,
    /// so the caller can still report the original write failure.
    fn enqueue(&self, failed: Vec<Orphan>) -> Result<(), ShatterError> {
        let mut queue = self.orphans.lock().map_err(|_| ShatterError::Internal)?;
        let persisted = match &self.orphan_log {
            Some(log) => log.append(&failed),
            None => Ok(()),
        };
        queue.extend(failed);
        persisted
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
                body: add_schema_version(self.schema.version(), &encode_fields(fields)?),
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
            // Saga compensation. The caller needs the cause, so a failed compensating
            // delete is queued as an orphan for `reap` instead of replacing the error.
            let failed: Vec<Orphan> = plan
                .iter()
                .filter(|p| written.contains(&p.vault))
                .filter(|p| router.delete(p.vault, &p.id).is_err())
                .map(|p| Orphan {
                    vault: p.vault,
                    id: p.id.clone(),
                    attempts: 0,
                })
                .collect();
            if !failed.is_empty() {
                // The cause is what the caller needs, so a log write failure is not
                // returned here. The orphans stay queued in RAM either way.
                let _ = self.enqueue(failed);
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

#[cfg(test)]
mod reap_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tpt_shatter_common::SHARD_KEY_LEN;
    use tpt_shatter_vault_client::{
        BreakerConfig, Guarded, MemoryVault, VaultBackend, system_clock,
    };

    const KEY: [u8; 32] = [0x99; 32];

    /// Passes every call through except `delete`, which fails while `fail_delete` is set.
    struct DeleteFlaky {
        inner: Arc<MemoryVault>,
        fail_delete: Arc<AtomicBool>,
    }

    impl VaultBackend for DeleteFlaky {
        fn vault(&self) -> VaultId {
            self.inner.vault()
        }
        fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
            self.inner.put(id, bytes)
        }
        fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
            self.inner.get(id)
        }
        fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
            if self.fail_delete.load(Ordering::SeqCst) {
                Err(ShatterError::VaultUnavailable {
                    vault: self.inner.vault(),
                })
            } else {
                self.inner.delete(id)
            }
        }
    }

    struct Fx {
        schema: ShatterSchema,
        router: Router,
        vaults: Vec<Arc<MemoryVault>>,
        fail_delete: Vec<Arc<AtomicBool>>,
    }

    fn fixture() -> Fx {
        let schema = ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("schema");
        let mut vaults = Vec::new();
        let mut fail_delete = Vec::new();
        let mut guards = Vec::new();
        for v in VaultId::ALL {
            let inner = Arc::new(MemoryVault::new(v));
            let flag = Arc::new(AtomicBool::new(false));
            guards.push(Guarded::new(
                Box::new(DeleteFlaky {
                    inner: Arc::clone(&inner),
                    fail_delete: Arc::clone(&flag),
                }),
                BreakerConfig {
                    attempts: 1,
                    failure_threshold: 1000,
                    ..BreakerConfig::default()
                },
                system_clock(),
            ));
            vaults.push(inner);
            fail_delete.push(flag);
        }
        Fx {
            schema,
            router: Router::new(guards).expect("router"),
            vaults,
            fail_delete,
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
        ShardKey::from_bytes([5; SHARD_KEY_LEN])
    }

    /// Vault B refuses writes, and vaults A and C refuse the compensating deletes, so
    /// two orphans are left behind.
    fn stranded(f: &Fx) -> Shredder<'_> {
        f.vaults[1].set_available(false);
        f.fail_delete[0].store(true, Ordering::SeqCst);
        f.fail_delete[2].store(true, Ordering::SeqCst);
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        assert_eq!(
            shredder.shred(&shard(), record()),
            Err(ShatterError::VaultUnavailable { vault: VaultId::B })
        );
        shredder
    }

    #[test]
    fn failed_compensations_are_queued_and_reaped_once_the_vault_recovers() {
        let f = fixture();
        let shredder = stranded(&f);
        assert_eq!(shredder.pending_orphans(), Ok(2));
        assert_eq!(f.vaults[0].row_count(), Ok(1));

        let first = shredder.reap(3).expect("reap");
        assert_eq!(
            first,
            ReapReport {
                removed: 0,
                still_pending: 2,
                abandoned: 0
            }
        );
        assert_eq!(shredder.pending_orphans(), Ok(2));

        f.fail_delete[0].store(false, Ordering::SeqCst);
        f.fail_delete[2].store(false, Ordering::SeqCst);
        let second = shredder.reap(3).expect("reap");
        assert_eq!(second.removed, 2);
        assert_eq!(shredder.pending_orphans(), Ok(0));
        assert_eq!(f.vaults[0].row_count(), Ok(0));
        assert_eq!(f.vaults[2].row_count(), Ok(0));
    }

    #[test]
    fn orphans_are_abandoned_after_max_attempts() {
        let f = fixture();
        let shredder = stranded(&f);
        let report = shredder.reap(1).expect("reap");
        assert_eq!(
            report,
            ReapReport {
                removed: 0,
                still_pending: 0,
                abandoned: 2
            }
        );
        assert_eq!(shredder.pending_orphans(), Ok(0));
    }

    #[test]
    fn reap_rejects_zero_attempts() {
        let f = fixture();
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        assert_eq!(shredder.reap(0), Err(ShatterError::InvalidParameter));
    }

    #[test]
    fn a_clean_shred_queues_nothing() {
        let f = fixture();
        let shredder = Shredder::new(&f.schema, &f.router, KEY);
        shredder.shred(&shard(), record()).expect("shred");
        assert_eq!(shredder.pending_orphans(), Ok(0));
    }

    #[test]
    fn orphans_survive_a_restart_and_are_reaped_by_the_new_shredder() {
        let f = fixture();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("tpt-shatter-restart-{nanos}.jsonl"));

        f.vaults[1].set_available(false);
        f.fail_delete[0].store(true, Ordering::SeqCst);
        f.fail_delete[2].store(true, Ordering::SeqCst);
        let before = Shredder::with_orphan_log(&f.schema, &f.router, KEY, &path).expect("open");
        assert!(before.shred(&shard(), record()).is_err());
        assert_eq!(before.pending_orphans(), Ok(2));
        drop(before);

        // Simulated restart: the new shredder must see the two orphans from the file.
        f.vaults[1].set_available(true);
        f.fail_delete[0].store(false, Ordering::SeqCst);
        f.fail_delete[2].store(false, Ordering::SeqCst);
        let after = Shredder::with_orphan_log(&f.schema, &f.router, KEY, &path).expect("reopen");
        assert_eq!(after.pending_orphans(), Ok(2));
        let report = after.reap(3).expect("reap");
        assert_eq!(report.removed, 2);
        assert_eq!(f.vaults[0].row_count(), Ok(0));
        assert_eq!(f.vaults[2].row_count(), Ok(0));
        drop(after);

        // The reap rewrote the file, so a third start finds an empty queue.
        let third = Shredder::with_orphan_log(&f.schema, &f.router, KEY, &path).expect("third");
        assert_eq!(third.pending_orphans(), Ok(0));
        drop(third);
        std::fs::remove_file(&path).expect("cleanup");
    }
}
