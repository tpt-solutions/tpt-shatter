// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Durable storage for the orphan queue.
//!
//! The file holds one JSON object per line: `{"vault":"B","id":"<64 hex>"}`. A
//! FragmentId is a keyed, opaque value and reveals nothing without the derivation key,
//! so it is safe to store. Field values are never written here.
//!
//! Attempt counts are not stored. After a restart every orphan starts again at zero.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tpt_shatter_common::{FRAGMENT_ID_LEN, FragmentId, ShatterError, VaultId};

/// A fragment whose compensating delete failed and is waiting for a reap.
#[derive(Clone)]
pub(crate) struct Orphan {
    pub(crate) vault: VaultId,
    pub(crate) id: FragmentId,
    pub(crate) attempts: u32,
}

/// Append-only file backing the orphan queue.
pub(crate) struct OrphanLog {
    path: PathBuf,
}

impl OrphanLog {
    /// Opens the log at `path` and returns every orphan it holds. A missing file is empty.
    pub(crate) fn open(path: &Path) -> Result<(Self, Vec<Orphan>), ShatterError> {
        let orphans = match File::open(path) {
            Ok(file) => BufReader::new(file)
                .lines()
                .map(|line| {
                    let line = line.map_err(|_| ShatterError::Internal)?;
                    parse_line(&line)
                })
                .collect::<Result<Vec<_>, _>>()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(ShatterError::Internal),
        };
        Ok((
            Self {
                path: path.to_path_buf(),
            },
            orphans,
        ))
    }

    /// Appends orphans and syncs them to disk before returning.
    pub(crate) fn append(&self, orphans: &[Orphan]) -> Result<(), ShatterError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| ShatterError::Internal)?;
        file.write_all(&encode(orphans)?)
            .map_err(|_| ShatterError::Internal)?;
        file.sync_data().map_err(|_| ShatterError::Internal)
    }

    /// Replaces the whole log with `orphans`.
    ///
    /// Writes a temporary file, syncs it, then renames it over the log, so a crash
    /// leaves either the old or the new contents.
    pub(crate) fn replace(&self, orphans: &[Orphan]) -> Result<(), ShatterError> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut file = File::create(&tmp).map_err(|_| ShatterError::Internal)?;
            file.write_all(&encode(orphans)?)
                .map_err(|_| ShatterError::Internal)?;
            file.sync_all().map_err(|_| ShatterError::Internal)?;
        }
        fs::rename(&tmp, &self.path).map_err(|_| ShatterError::Internal)
    }
}

fn encode(orphans: &[Orphan]) -> Result<Vec<u8>, ShatterError> {
    let mut out = Vec::new();
    for orphan in orphans {
        let line = json!({
            "vault": orphan.vault.label().to_string(),
            "id": hex(orphan.id.as_bytes()),
        });
        serde_json::to_writer(&mut out, &line).map_err(|_| ShatterError::Internal)?;
        out.push(b'\n');
    }
    Ok(out)
}

fn parse_line(line: &str) -> Result<Orphan, ShatterError> {
    let value: Value = serde_json::from_str(line).map_err(|_| ShatterError::Internal)?;
    let label = value
        .get("vault")
        .and_then(Value::as_str)
        .and_then(|s| s.chars().next())
        .ok_or(ShatterError::Internal)?;
    let id_hex = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ShatterError::Internal)?;
    let id = FragmentId::from_hex(id_hex).map_err(|_| ShatterError::Internal)?;
    Ok(Orphan {
        vault: VaultId::from_label(label).map_err(|_| ShatterError::Internal)?,
        id,
        attempts: 0,
    })
}

fn hex(bytes: &[u8; FRAGMENT_ID_LEN]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(FRAGMENT_ID_LEN * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-orphans-{name}-{nanos}.jsonl"))
    }

    fn orphan(vault: VaultId, byte: u8) -> Orphan {
        Orphan {
            vault,
            id: FragmentId::from_bytes([byte; FRAGMENT_ID_LEN]),
            attempts: 3,
        }
    }

    #[test]
    fn missing_file_opens_empty() {
        let path = temp_path("missing");
        let (_, orphans) = OrphanLog::open(&path).expect("open");
        assert!(orphans.is_empty());
    }

    #[test]
    fn appended_orphans_come_back_on_reopen_with_attempts_reset() {
        let path = temp_path("append");
        let (log, _) = OrphanLog::open(&path).expect("open");
        log.append(&[orphan(VaultId::A, 1), orphan(VaultId::C, 2)])
            .expect("append");
        let (_, back) = OrphanLog::open(&path).expect("reopen");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].vault, VaultId::A);
        assert_eq!(back[0].id.as_bytes(), &[1; FRAGMENT_ID_LEN]);
        assert_eq!(back[1].vault, VaultId::C);
        assert_eq!(back[1].attempts, 0);
    }

    #[test]
    fn replace_keeps_only_the_given_orphans() {
        let path = temp_path("replace");
        let (log, _) = OrphanLog::open(&path).expect("open");
        log.append(&[orphan(VaultId::A, 1), orphan(VaultId::B, 2)])
            .expect("append");
        log.replace(&[orphan(VaultId::B, 2)]).expect("replace");
        let (_, back) = OrphanLog::open(&path).expect("reopen");
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].vault, VaultId::B);
    }

    #[test]
    fn malformed_line_fails_the_open() {
        let path = temp_path("malformed");
        std::fs::write(&path, "{\"vault\":\"Z\",\"id\":\"00\"}\n").expect("write");
        let result = OrphanLog::open(&path).err();
        std::fs::remove_file(&path).expect("cleanup");
        assert_eq!(result, Some(ShatterError::Internal));
    }
}
