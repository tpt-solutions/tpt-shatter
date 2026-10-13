// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Ephemeral reconstruction of records from their fragments.
//!
//! [`Assembler::assemble`] re-derives each vault's fragment ID from the shard key,
//! fetches all three fragments in parallel, and rebuilds the record in RAM. It fails
//! closed: a missing, malformed, or misplaced fragment returns an error, and no partial
//! record is ever returned.
//!
//! [`migrate_shard`] re-shatters one shard from one schema version to another.
//!
//! [`assemble_with_deadline`] bounds a reconstruction by a deadline.
//!
//! Not implemented yet: mlock and RLIMIT_CORE hardening,
//! the internal gRPC interface with mTLS, and the statically linked musl build. Those
//! need Linux host work (see the Phase 7 checklist).

mod migrate;

pub use migrate::migrate_shard;

use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use tpt_shatter_common::{Record, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_vault_client::{Router, decode_fields, derive_fragment_id, split_schema_version};
use zeroize::Zeroizing;

/// One fragment body, zeroed on drop because it holds field values.
type Body = Zeroizing<Vec<u8>>;

/// A vault's fetch result: `None` means the fragment is absent.
type Fetched = (VaultId, Result<Option<Body>, ShatterError>);

/// Rebuilds records from fragments held in the vaults.
pub struct Assembler<'a> {
    schema: &'a ShatterSchema,
    router: &'a Router,
    derivation_key: Zeroizing<[u8; 32]>,
}

impl<'a> Assembler<'a> {
    /// Creates an assembler. `derivation_key` is held in RAM and zeroed on drop.
    #[must_use]
    pub fn new(schema: &'a ShatterSchema, router: &'a Router, derivation_key: [u8; 32]) -> Self {
        Self {
            schema,
            router,
            derivation_key: Zeroizing::new(derivation_key),
        }
    }

    /// Reassembles the record stored under `shard`.
    ///
    /// Returns [`ShatterError::Reconstruction`] if any vault's fragment is missing,
    /// malformed, or holds a field the schema assigns to a different vault. A vault
    /// outage returns [`ShatterError::VaultUnavailable`]. In every error case the
    /// partially built record is dropped and its values are zeroed.
    pub fn assemble(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        let bodies = self.fetch(shard)?;
        build_record(self.schema, &bodies)
    }

    /// Fetches the fragment body for every vault in parallel. Any gap is an error.
    fn fetch(&self, shard: &ShardKey) -> Result<Vec<(VaultId, Body)>, ShatterError> {
        let router = self.router;
        let key = &self.derivation_key[..];
        let results: Vec<Fetched> = thread::scope(|scope| {
            let handles: Vec<_> = VaultId::ALL
                .iter()
                .map(|vault| {
                    let vault = *vault;
                    (
                        vault,
                        scope.spawn(move || {
                            let id = derive_fragment_id(key, shard, vault)?;
                            router.get(vault, &id)
                        }),
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

        let mut bodies = Vec::with_capacity(results.len());
        for (vault, result) in results {
            match result? {
                Some(body) => bodies.push((vault, body)),
                None => return Err(ShatterError::Reconstruction),
            }
        }
        Ok(bodies)
    }
}

/// Reassembles the record under `shard`, giving up once `deadline` has passed.
///
/// Behaves like [`Assembler::assemble`], with one addition: each vault is fetched on its
/// own thread, and if any fetch has not returned by the deadline the call fails with
/// [`ShatterError::VaultUnavailable`] for the first vault still outstanding. No partial
/// record is returned.
///
/// A fetch that misses the deadline is not cancelled, because a vault call cannot be
/// interrupted. It finishes in the background, and its result is dropped, zeroing its
/// bytes, when the receiver is gone. The derivation key is used only on this thread.
pub fn assemble_with_deadline(
    schema: &ShatterSchema,
    router: &Arc<Router>,
    derivation_key: &[u8; 32],
    shard: &ShardKey,
    deadline: Duration,
) -> Result<Record, ShatterError> {
    let (tx, rx) = mpsc::channel::<Fetched>();
    for vault in VaultId::ALL {
        // Derive on this thread, so only the FragmentId and the router cross over.
        let id = derive_fragment_id(&derivation_key[..], shard, vault)?;
        let router = Arc::clone(router);
        let tx = tx.clone();
        thread::spawn(move || {
            let result = router.get(vault, &id);
            // A send fails once the caller has timed out. The late body is dropped here.
            let _ = tx.send((vault, result));
        });
    }
    drop(tx);

    let end = Instant::now() + deadline;
    let mut results: Vec<Fetched> = Vec::with_capacity(VaultId::ALL.len());
    while results.len() < VaultId::ALL.len() {
        match rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok(item) => results.push(item),
            Err(RecvTimeoutError::Timeout) => {
                let missing = VaultId::ALL
                    .into_iter()
                    .find(|v| !results.iter().any(|(done, _)| done == v))
                    .unwrap_or(VaultId::A);
                return Err(ShatterError::VaultUnavailable { vault: missing });
            }
            // A fetch thread ended without sending, which means it panicked.
            Err(RecvTimeoutError::Disconnected) => return Err(ShatterError::Internal),
        }
    }

    let mut bodies = Vec::with_capacity(results.len());
    for (vault, result) in results {
        match result? {
            Some(body) => bodies.push((vault, body)),
            None => return Err(ShatterError::Reconstruction),
        }
    }
    build_record(schema, &bodies)
}

/// Builds a record from one body per vault. Any version, placement, or duplication
/// error fails the whole build.
fn build_record(
    schema: &ShatterSchema,
    bodies: &[(VaultId, Body)],
) -> Result<Record, ShatterError> {
    let mut record = Record::new();
    for (vault, body) in bodies {
        // A fragment written under another schema version cannot be read safely,
        // so it is refused the same way as a malformed one.
        let (version, fields) = split_schema_version(body)?;
        if version != schema.version() {
            return Err(ShatterError::Reconstruction);
        }
        for (name, value) in decode_fields(fields)? {
            if schema.vault_for(&name) != Some(*vault) {
                return Err(ShatterError::Reconstruction);
            }
            if record.insert(name, value.as_str()).is_some() {
                return Err(ShatterError::Reconstruction);
            }
        }
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_shatter_common::{FragmentId, SHARD_KEY_LEN};
    use tpt_shatter_shredder::{Shredder, erase};
    use tpt_shatter_vault_client::{
        BreakerConfig, Guarded, MemoryVault, VaultBackend, system_clock,
    };

    const KEY: [u8; 32] = [0x99; 32];

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
        Fixture {
            schema,
            router: Router::new(guards).expect("router"),
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
        ShardKey::from_bytes([4; SHARD_KEY_LEN])
    }

    fn fragment_id(vault: VaultId) -> FragmentId {
        derive_fragment_id(&KEY, &shard(), vault).expect("id")
    }

    fn shred(f: &Fixture) {
        Shredder::new(&f.schema, &f.router, KEY)
            .shred(&shard(), record())
            .expect("shred");
    }

    #[test]
    fn reconstructs_exactly_what_was_shredded() {
        let f = fixture();
        shred(&f);
        let rebuilt = Assembler::new(&f.schema, &f.router, KEY)
            .assemble(&shard())
            .expect("assemble");
        assert_eq!(rebuilt.len(), 3);
        assert_eq!(rebuilt.get("name"), Some("A. Example"));
        assert_eq!(rebuilt.get("birth_year"), Some("1990"));
        assert_eq!(rebuilt.get("card_number"), Some("4111111111111111"));
    }

    #[test]
    fn missing_fragment_yields_no_partial_record() {
        let f = fixture();
        shred(&f);
        f.router
            .delete(VaultId::B, &fragment_id(VaultId::B))
            .expect("delete");
        assert_eq!(
            Assembler::new(&f.schema, &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn outage_is_reported_as_unavailable() {
        let f = fixture();
        shred(&f);
        f.vaults[0].set_available(false);
        assert_eq!(
            Assembler::new(&f.schema, &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::VaultUnavailable { vault: VaultId::A })
        );
    }

    #[test]
    fn wrong_key_finds_nothing() {
        let f = fixture();
        shred(&f);
        let wrong = [0x11; 32];
        assert_eq!(
            Assembler::new(&f.schema, &f.router, wrong)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn fragment_from_another_schema_version_is_rejected() {
        use tpt_shatter_vault_client::add_schema_version;
        let f = fixture();
        shred(&f);
        // Re-store vault A's fields under schema version 2. The version check must refuse it.
        let body = f
            .router
            .get(VaultId::A, &fragment_id(VaultId::A))
            .expect("get")
            .expect("present");
        let (_, fields) = split_schema_version(&body).expect("split");
        let rewritten = add_schema_version(2, fields);
        f.router
            .put(VaultId::A, &fragment_id(VaultId::A), &rewritten)
            .expect("put");
        assert_eq!(
            Assembler::new(&f.schema, &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn misplaced_fragment_is_rejected() {
        let f = fixture();
        shred(&f);
        // Copy vault A's fragment into vault B's slot. Its field "name" belongs to A.
        let a_body = f
            .router
            .get(VaultId::A, &fragment_id(VaultId::A))
            .expect("get")
            .expect("present");
        f.router
            .put(VaultId::B, &fragment_id(VaultId::B), &a_body)
            .expect("put");
        assert_eq!(
            Assembler::new(&f.schema, &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn malformed_fragment_is_rejected() {
        let f = fixture();
        shred(&f);
        f.router
            .put(
                VaultId::C,
                &fragment_id(VaultId::C),
                &[0xFF, 0xFF, 0xFF, 0xFF],
            )
            .expect("put");
        assert_eq!(
            Assembler::new(&f.schema, &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }

    /// Reads from vault A wait `delay` before answering. Writes are not delayed.
    struct SlowRead {
        inner: Arc<MemoryVault>,
        delay: Duration,
    }

    impl VaultBackend for SlowRead {
        fn vault(&self) -> VaultId {
            self.inner.vault()
        }

        fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
            self.inner.put(id, bytes)
        }

        fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
            thread::sleep(self.delay);
            self.inner.get(id)
        }

        fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
            self.inner.delete(id)
        }
    }

    /// Shreds the record through a router where vault A's reads take `delay`.
    fn timed_router(delay: Duration) -> (ShatterSchema, Arc<Router>) {
        let schema = ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("schema");
        let guards = VaultId::ALL
            .iter()
            .map(|v| {
                let inner = Arc::new(MemoryVault::new(*v));
                let backend: Box<dyn VaultBackend> = if *v == VaultId::A {
                    Box::new(SlowRead { inner, delay })
                } else {
                    Box::new(inner)
                };
                Guarded::new(backend, BreakerConfig::default(), system_clock())
            })
            .collect();
        let router = Arc::new(Router::new(guards).expect("router"));
        let mut r = Record::new();
        r.insert("name", "A. Example");
        r.insert("birth_year", "1990");
        r.insert("card_number", "4111111111111111");
        Shredder::new(&schema, &router, KEY)
            .shred(&shard(), r)
            .expect("shred");
        (schema, router)
    }

    #[test]
    fn a_fetch_within_the_deadline_reconstructs_the_record() {
        let (schema, router) = timed_router(Duration::ZERO);
        let rebuilt =
            assemble_with_deadline(&schema, &router, &KEY, &shard(), Duration::from_secs(5))
                .expect("assemble");
        assert_eq!(rebuilt.get("name"), Some("A. Example"));
        assert_eq!(rebuilt.len(), 3);
    }

    #[test]
    fn a_vault_slower_than_the_deadline_fails_as_unavailable() {
        let (schema, router) = timed_router(Duration::from_secs(2));
        assert_eq!(
            assemble_with_deadline(&schema, &router, &KEY, &shard(), Duration::from_millis(100),)
                .err(),
            Some(ShatterError::VaultUnavailable { vault: VaultId::A })
        );
    }

    #[test]
    fn the_deadline_path_still_refuses_a_missing_fragment() {
        let (schema, router) = timed_router(Duration::ZERO);
        let id = derive_fragment_id(&KEY, &shard(), VaultId::C).expect("id");
        router.delete_maintenance(VaultId::C, &id).expect("delete");
        assert_eq!(
            assemble_with_deadline(&schema, &router, &KEY, &shard(), Duration::from_secs(5),).err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn erased_shard_cannot_be_reassembled() {
        let f = fixture();
        shred(&f);
        erase(&f.router, &KEY, &shard()).expect("erase");
        assert_eq!(
            Assembler::new(&f.schema, &f.router, KEY)
                .assemble(&shard())
                .err(),
            Some(ShatterError::Reconstruction)
        );
    }
}
