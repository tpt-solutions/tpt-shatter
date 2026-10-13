// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Internal vault storage: one directory per vault, one encrypted file per fragment.
//!
//! This replaces the keystone database for fragment storage. Its properties:
//!
//! - **Encrypted at rest.** Each fragment is sealed with ChaCha20-Poly1305 under the
//!   vault's own key. The associated data is the vault label, the FragmentId, and the
//!   time the fragment was stored, so a file moved to another vault or another ID, or
//!   with its timestamp changed, fails to open.
//! - **Retention.** Each file records when it was stored. [`FileVault::purge_expired`]
//!   erases the files whose [`RetentionPolicy`] has run out.
//! - **Atomic writes.** A put writes a temporary file, syncs it, and renames it into
//!   place. A crash leaves the old or the new contents, never a partial one.
//! - **Physical erasure.** A delete or purge overwrites the file with zeros, syncs, then
//!   removes it. No change feed or history keeps the bytes.
//! - **Isolation by directory and key.** Each vault has its own directory and key. The
//!   keys are supplied by the caller and held in RAM.
//!
//! File layout: `nonce (12) || stored_at (8, big-endian Unix seconds) || sealed`.
//!
//! Limits: erasure overwrites in place, which is not guaranteed on SSDs with wear
//! leveling or copy-on-write file systems. Backups are outside this module.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tpt_shatter_common::{FRAGMENT_ID_LEN, FragmentId, RetentionPolicy, ShatterError, VaultId};
use zeroize::Zeroizing;

use crate::backend::VaultBackend;

const NONCE_LEN: usize = 12;
const STAMP_LEN: usize = 8;
const TAG_LEN: usize = 16;
const FRAGMENT_EXT: &str = "frag";
const TEMP_EXT: &str = "tmp";

/// What a [`FileVault::purge_expired`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    /// Expired fragments that were erased.
    pub purged: usize,
    /// Files that did not authenticate. They are left in place for an operator.
    pub malformed: usize,
}

/// A vault stored as encrypted files in a directory of its own.
pub struct FileVault {
    vault: VaultId,
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
    /// Serializes puts, deletes, and purges, so a purge never erases a file that a
    /// concurrent put has just replaced.
    lifecycle: Mutex<()>,
}

impl FileVault {
    /// Opens the vault stored in `dir`, creating the directory if needed.
    ///
    /// Temporary files left by an interrupted put are removed here, so they never
    /// accumulate. `key` is the vault's sealing key. It is copied into the cipher and
    /// the caller should zero its own copy.
    pub fn open(vault: VaultId, dir: &Path, key: &[u8; 32]) -> Result<Self, ShatterError> {
        fs::create_dir_all(dir).map_err(|_| unavailable(vault))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| ShatterError::InvalidParameter)?;
        let vault_dir = Self {
            vault,
            dir: dir.to_path_buf(),
            cipher,
            lifecycle: Mutex::new(()),
        };
        for entry in fs::read_dir(dir).map_err(|_| unavailable(vault))? {
            let path = entry.map_err(|_| unavailable(vault))?.path();
            if path.extension().and_then(|e| e.to_str()) == Some(TEMP_EXT) {
                fs::remove_file(&path).map_err(|_| unavailable(vault))?;
            }
        }
        Ok(vault_dir)
    }

    /// Erases every fragment whose retention has run out at `now` (Unix seconds).
    ///
    /// A file is erased only if it authenticates under this vault's key and its own
    /// name. A file that fails is counted in the report and left alone, so a tampered
    /// file is never silently destroyed.
    pub fn purge_expired(
        &self,
        policy: RetentionPolicy,
        now: u64,
    ) -> Result<PurgeReport, ShatterError> {
        let _guard = self.lifecycle()?;
        let mut report = PurgeReport::default();
        for entry in fs::read_dir(&self.dir).map_err(|_| unavailable(self.vault))? {
            let path = entry.map_err(|_| unavailable(self.vault))?.path();
            if path.extension().and_then(|e| e.to_str()) != Some(FRAGMENT_EXT) {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).and_then(parse_id) else {
                report.malformed += 1;
                continue;
            };
            let Ok(file_bytes) = fs::read(&path).map(Zeroizing::new) else {
                report.malformed += 1;
                continue;
            };
            let Ok((stored_at, _plain)) = self.open_file(&id, &file_bytes) else {
                report.malformed += 1;
                continue;
            };
            if policy.is_expired(stored_at, now) {
                erase_file(self.vault, &path)?;
                report.purged += 1;
            }
        }
        Ok(report)
    }

    fn path(&self, id: &FragmentId) -> PathBuf {
        self.dir
            .join(format!("{}.{FRAGMENT_EXT}", hex(id.as_bytes())))
    }

    fn lifecycle(&self) -> Result<MutexGuard<'_, ()>, ShatterError> {
        self.lifecycle.lock().map_err(|_| ShatterError::Internal)
    }

    /// Associated data: the vault label, the FragmentId, then the stored-at time.
    /// Binds each file to its place and its time.
    fn aad(&self, id: &FragmentId, stamp: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + FRAGMENT_ID_LEN + STAMP_LEN);
        aad.push(self.vault.label() as u8);
        aad.extend_from_slice(id.as_bytes());
        aad.extend_from_slice(stamp);
        aad
    }

    /// Authenticates and opens a file's bytes. Returns the stored-at time and the plaintext.
    fn open_file(
        &self,
        id: &FragmentId,
        file_bytes: &[u8],
    ) -> Result<(u64, Zeroizing<Vec<u8>>), ShatterError> {
        if file_bytes.len() < NONCE_LEN + STAMP_LEN + TAG_LEN {
            return Err(ShatterError::Reconstruction);
        }
        let (nonce, rest) = file_bytes.split_at(NONCE_LEN);
        let (stamp, sealed) = rest.split_at(STAMP_LEN);
        // A wrong key, a modified file, a changed timestamp, or a file moved from
        // another place all fail here.
        let plain = self
            .cipher
            .decrypt(
                &Nonce::try_from(nonce).map_err(|_| ShatterError::Reconstruction)?,
                Payload {
                    msg: sealed,
                    aad: &self.aad(id, stamp),
                },
            )
            .map_err(|_| ShatterError::Reconstruction)?;
        let stored_at =
            u64::from_be_bytes(stamp.try_into().map_err(|_| ShatterError::Reconstruction)?);
        Ok((stored_at, Zeroizing::new(plain)))
    }
}

impl VaultBackend for FileVault {
    fn vault(&self) -> VaultId {
        self.vault
    }

    fn put(&self, id: &FragmentId, bytes: &[u8]) -> Result<(), ShatterError> {
        let _guard = self.lifecycle()?;
        let stored_at = unix_now()?;
        let stamp = stored_at.to_be_bytes();
        let nonce = random_nonce();
        let sealed = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: bytes,
                    aad: &self.aad(id, &stamp),
                },
            )
            .map_err(|_| ShatterError::Internal)?;
        let mut file_bytes = Vec::with_capacity(NONCE_LEN + STAMP_LEN + sealed.len());
        file_bytes.extend_from_slice(&nonce);
        file_bytes.extend_from_slice(&stamp);
        file_bytes.extend_from_slice(&sealed);

        let target = self.path(id);
        let temp = self.dir.join(format!(
            "{}.{}.{TEMP_EXT}",
            hex(id.as_bytes()),
            hex(&random_nonce())
        ));
        {
            let mut file = File::create(&temp).map_err(|_| unavailable(self.vault))?;
            file.write_all(&file_bytes)
                .map_err(|_| unavailable(self.vault))?;
            file.sync_all().map_err(|_| unavailable(self.vault))?;
        }
        fs::rename(&temp, &target).map_err(|_| unavailable(self.vault))
    }

    fn get(&self, id: &FragmentId) -> Result<Option<Zeroizing<Vec<u8>>>, ShatterError> {
        let mut file_bytes = Vec::new();
        match File::open(self.path(id)) {
            Ok(mut file) => file
                .read_to_end(&mut file_bytes)
                .map_err(|_| unavailable(self.vault))?,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unavailable(self.vault)),
        };
        let file_bytes = Zeroizing::new(file_bytes);
        let (_stored_at, plain) = self.open_file(id, &file_bytes)?;
        Ok(Some(plain))
    }

    fn delete(&self, id: &FragmentId) -> Result<bool, ShatterError> {
        let _guard = self.lifecycle()?;
        let path = self.path(id);
        match fs::metadata(&path) {
            Ok(_) => erase_file(self.vault, &path),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(_) => Err(unavailable(self.vault)),
        }
    }
}

/// Overwrites a file with zeros, syncs it, and removes it. Returns `false` if it was missing.
fn erase_file(vault: VaultId, path: &Path) -> Result<bool, ShatterError> {
    let len = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(unavailable(vault)),
    };
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| unavailable(vault))?;
        let zeros = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        file.write_all(&zeros).map_err(|_| unavailable(vault))?;
        file.sync_all().map_err(|_| unavailable(vault))?;
    }
    fs::remove_file(path).map_err(|_| unavailable(vault))?;
    Ok(true)
}

fn unavailable(vault: VaultId) -> ShatterError {
    ShatterError::VaultUnavailable { vault }
}

fn unix_now() -> Result<u64, ShatterError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ShatterError::Internal)
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[..8].copy_from_slice(&rand::random::<u64>().to_be_bytes());
    out[8..].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Parses a file stem written by [`hex`] back into a FragmentId. Anything else is `None`.
fn parse_id(name: &str) -> Option<FragmentId> {
    if !name.is_ascii() || name.len() != 2 * FRAGMENT_ID_LEN {
        return None;
    }
    let mut bytes = [0u8; FRAGMENT_ID_LEN];
    for (i, out) in bytes.iter_mut().enumerate() {
        *out = u8::from_str_radix(&name[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(FragmentId::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: [u8; 32] = [0x11; 32];
    const KEY_B: [u8; 32] = [0x22; 32];

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-filevault-{name}-{nanos}"))
    }

    fn id(byte: u8) -> FragmentId {
        FragmentId::from_bytes([byte; FRAGMENT_ID_LEN])
    }

    fn only_fragment_file(dir: &Path) -> PathBuf {
        fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").path())
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some(FRAGMENT_EXT))
            .expect("one fragment file")
    }

    fn fragment_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .expect("read dir")
            .filter(|e| {
                let p = e.as_ref().expect("entry").path();
                p.extension().and_then(|x| x.to_str()) == Some(FRAGMENT_EXT)
            })
            .count()
    }

    #[test]
    fn put_get_delete_round_trip() {
        let dir = temp_dir("roundtrip");
        let vault = FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        vault.put(&id(1), b"fragment body").expect("put");
        assert_eq!(
            vault.get(&id(1)).expect("get").expect("present").as_slice(),
            b"fragment body"
        );
        assert_eq!(vault.get(&id(2)).expect("get"), None);
        assert_eq!(vault.delete(&id(1)), Ok(true));
        assert_eq!(vault.get(&id(1)).expect("get"), None);
        assert_eq!(vault.delete(&id(1)), Ok(false));
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn fragments_survive_reopening_the_vault() {
        let dir = temp_dir("reopen");
        FileVault::open(VaultId::B, &dir, &KEY_A)
            .expect("open")
            .put(&id(7), b"kept")
            .expect("put");
        let reopened = FileVault::open(VaultId::B, &dir, &KEY_A).expect("reopen");
        assert_eq!(
            reopened
                .get(&id(7))
                .expect("get")
                .expect("present")
                .as_slice(),
            b"kept"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn plaintext_does_not_appear_on_disk() {
        let dir = temp_dir("plaintext");
        let vault = FileVault::open(VaultId::C, &dir, &KEY_A).expect("open");
        let secret = b"4111111111111111-secret-marker";
        vault.put(&id(3), secret).expect("put");
        let on_disk = fs::read(only_fragment_file(&dir)).expect("read");
        fs::remove_dir_all(&dir).expect("cleanup");
        assert!(!on_disk.windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn a_modified_file_is_refused() {
        let dir = temp_dir("tamper");
        let vault = FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        vault.put(&id(4), b"original").expect("put");
        let path = only_fragment_file(&dir);
        let mut bytes = fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).expect("write");
        let result = vault.get(&id(4));
        fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(result.err(), Some(ShatterError::Reconstruction));
    }

    #[test]
    fn a_changed_storage_time_is_refused() {
        let dir = temp_dir("stamp");
        let vault = FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        vault.put(&id(10), b"dated").expect("put");
        let path = only_fragment_file(&dir);
        let mut bytes = fs::read(&path).expect("read");
        // Push the stored-at time forward so the fragment looks newer than it is.
        bytes[NONCE_LEN + STAMP_LEN - 1] ^= 0x01;
        fs::write(&path, &bytes).expect("write");
        let result = vault.get(&id(10));
        fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(result.err(), Some(ShatterError::Reconstruction));
    }

    #[test]
    fn the_wrong_key_cannot_read_the_vault() {
        let dir = temp_dir("wrongkey");
        FileVault::open(VaultId::A, &dir, &KEY_A)
            .expect("open")
            .put(&id(5), b"secret")
            .expect("put");
        let other = FileVault::open(VaultId::A, &dir, &KEY_B).expect("open");
        let result = other.get(&id(5));
        fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(result.err(), Some(ShatterError::Reconstruction));
    }

    #[test]
    fn a_file_copied_to_another_vault_is_refused() {
        let dir_a = temp_dir("copy-a");
        let dir_b = temp_dir("copy-b");
        FileVault::open(VaultId::A, &dir_a, &KEY_A)
            .expect("open a")
            .put(&id(6), b"belongs to A")
            .expect("put");
        let vault_b = FileVault::open(VaultId::B, &dir_b, &KEY_A).expect("open b");
        // Copy A's file for this ID into B's directory under the same name.
        let src = only_fragment_file(&dir_a);
        fs::copy(&src, dir_b.join(src.file_name().expect("name"))).expect("copy");
        let result = vault_b.get(&id(6));
        fs::remove_dir_all(&dir_a).expect("cleanup");
        fs::remove_dir_all(&dir_b).expect("cleanup");
        assert_eq!(result.err(), Some(ShatterError::Reconstruction));
    }

    #[test]
    fn delete_removes_the_file() {
        let dir = temp_dir("erase");
        let vault = FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        vault.put(&id(8), b"to erase").expect("put");
        assert_eq!(vault.delete(&id(8)), Ok(true));
        let remaining = fs::read_dir(&dir).expect("read dir").count();
        fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(remaining, 0);
    }

    #[test]
    fn interrupted_temp_files_are_cleared_on_open() {
        let dir = temp_dir("temps");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join("stray.tmp"), b"partial").expect("write");
        FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        let left = fs::read_dir(&dir).expect("read dir").count();
        fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(left, 0);
    }

    #[test]
    fn purge_erases_only_fragments_past_their_retention() {
        let dir = temp_dir("purge");
        let vault = FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        vault.put(&id(20), b"one").expect("put");
        vault.put(&id(21), b"two").expect("put");
        let stored = unix_now().expect("now");
        let policy = RetentionPolicy::new(3600).expect("policy");

        // Well inside retention: nothing is purged.
        let early = vault.purge_expired(policy, stored + 60).expect("purge");
        assert_eq!(
            early,
            PurgeReport {
                purged: 0,
                malformed: 0
            }
        );
        assert_eq!(fragment_count(&dir), 2);

        // Past retention: both are erased, and the bytes are gone.
        let late = vault.purge_expired(policy, stored + 3600).expect("purge");
        assert_eq!(
            late,
            PurgeReport {
                purged: 2,
                malformed: 0
            }
        );
        assert_eq!(fragment_count(&dir), 0);
        assert_eq!(vault.get(&id(20)).expect("get"), None);
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn purge_leaves_a_file_that_does_not_authenticate() {
        let dir = temp_dir("purge-tamper");
        let vault = FileVault::open(VaultId::A, &dir, &KEY_A).expect("open");
        vault.put(&id(30), b"tampered").expect("put");
        let path = only_fragment_file(&dir);
        let mut bytes = fs::read(&path).expect("read");
        // Rewind the stored-at time so an unchecked purge would erase it at once.
        bytes[NONCE_LEN..NONCE_LEN + STAMP_LEN].copy_from_slice(&0u64.to_be_bytes());
        fs::write(&path, &bytes).expect("write");

        let policy = RetentionPolicy::new(60).expect("policy");
        let report = vault.purge_expired(policy, u64::MAX / 2).expect("purge");
        let still_there = path.exists();
        fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(
            report,
            PurgeReport {
                purged: 0,
                malformed: 1
            }
        );
        assert!(still_there, "an unauthenticated file must not be erased");
    }

    #[test]
    fn works_behind_the_router_with_three_vaults() {
        use crate::{BreakerConfig, Guarded, Router, system_clock};
        let dirs: Vec<PathBuf> = ["ra", "rb", "rc"].iter().map(|n| temp_dir(n)).collect();
        let guards = VaultId::ALL
            .iter()
            .zip(&dirs)
            .map(|(v, d)| {
                let backend = FileVault::open(*v, d, &KEY_A).expect("open");
                Guarded::new(
                    Box::new(backend),
                    BreakerConfig {
                        attempts: 1,
                        ..BreakerConfig::default()
                    },
                    system_clock(),
                )
            })
            .collect();
        let router = Router::new(guards).expect("router");
        router.put(VaultId::B, &id(9), b"b part").expect("put");
        let got = router.get(VaultId::B, &id(9)).expect("get");
        for d in &dirs {
            fs::remove_dir_all(d).expect("cleanup");
        }
        assert_eq!(got.expect("present").as_slice(), b"b part");
    }
}
