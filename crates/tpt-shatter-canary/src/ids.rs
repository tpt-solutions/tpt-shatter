// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The canary FragmentIds of one epoch, written by the node and read by the assembler.
//!
//! A detector needs only the FragmentIds, not the shard keys they came from. So the node can
//! hand the assembler this list, and the assembler never holds the canary key. The file is:
//!
//! ```text
//! tpt-shatter canary ids v1
//! epoch 2930
//! A 0 <64 hex characters>
//! ```
//!
//! The list shows where the canaries are, so it is protected like a key file. Writes are
//! atomic. On Unix, a read refuses a file readable or writable by group or others.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use tpt_shatter_common::{FragmentId, ShatterError, VaultId};

use crate::CanaryPlan;

const HEADER: &str = "tpt-shatter canary ids v1";
/// The most entries a list may hold. It bounds what a corrupt or hostile file can allocate.
const MAX_ENTRIES: usize = 65_536;

/// The canary FragmentIds of one epoch, each with its vault and canary index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryIds {
    epoch: u64,
    entries: Vec<(VaultId, usize, FragmentId)>,
}

impl CanaryIds {
    /// Lists the FragmentIds of `plan`, which must be the plan for `epoch`.
    pub fn from_plan(plan: &CanaryPlan, epoch: u64) -> Result<Self, ShatterError> {
        Self::new(epoch, plan.fragment_ids()?)
    }

    fn new(epoch: u64, entries: Vec<(VaultId, usize, FragmentId)>) -> Result<Self, ShatterError> {
        if entries.is_empty() || entries.len() > MAX_ENTRIES {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self { epoch, entries })
    }

    /// The rotation epoch these canaries belong to.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Each canary FragmentId, with its vault and canary index.
    #[must_use]
    pub fn entries(&self) -> &[(VaultId, usize, FragmentId)] {
        &self.entries
    }

    /// The list in the file format described in the module docs.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = format!("{HEADER}\nepoch {}\n", self.epoch);
        for (vault, index, id) in &self.entries {
            let _ = writeln!(text, "{} {index} {}", vault.label(), hex(id.as_bytes()));
        }
        text
    }

    /// Parses the file format. Any line that does not match is refused, so a damaged file
    /// is never partly used.
    pub fn parse(text: &str) -> Result<Self, ShatterError> {
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(ShatterError::InvalidParameter);
        }
        let epoch = lines
            .next()
            .and_then(|line| line.strip_prefix("epoch "))
            .and_then(|digits| digits.parse::<u64>().ok())
            .ok_or(ShatterError::InvalidParameter)?;
        let mut entries = Vec::new();
        for line in lines {
            let mut parts = line.split(' ');
            let (Some(label), Some(index), Some(id), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(ShatterError::InvalidParameter);
            };
            let mut label_chars = label.chars();
            let (Some(label), None) = (label_chars.next(), label_chars.next()) else {
                return Err(ShatterError::InvalidParameter);
            };
            let vault = VaultId::from_label(label)?;
            let index = index
                .parse::<usize>()
                .map_err(|_| ShatterError::InvalidParameter)?;
            entries.push((vault, index, FragmentId::from_hex(id)?));
        }
        Self::new(epoch, entries)
    }

    /// Writes the list to `path` atomically, readable only by its owner on Unix.
    pub fn write_file(&self, path: &Path) -> Result<(), ShatterError> {
        let tmp = path.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(|_| ShatterError::Internal)?;
        file.write_all(self.to_text().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| ShatterError::Internal)?;
        drop(file);
        fs::rename(&tmp, path).map_err(|_| ShatterError::Internal)
    }

    /// Reads and parses a list written by [`CanaryIds::write_file`]. On Unix, a file readable
    /// or writable by group or others is refused.
    pub fn read_file(path: &Path) -> Result<Self, ShatterError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .map_err(|_| ShatterError::Internal)?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(ShatterError::InvalidParameter);
            }
        }
        let text = fs::read_to_string(path).map_err(|_| ShatterError::Internal)?;
        Self::parse(&text)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanaryRotation, Detector};

    const MASTER: [u8; 32] = [0x91; 32];
    const DERIVATION: [u8; 32] = [0x92; 32];
    const WEEK: u64 = 7 * 24 * 3600;
    const NOW: u64 = 40 * WEEK + 3;

    fn ids() -> (CanaryRotation, CanaryIds) {
        let rotation = CanaryRotation::new(MASTER, DERIVATION, 3, WEEK).expect("rotation");
        let epoch = rotation.epoch(NOW).expect("epoch");
        let plan = rotation.plan_at(NOW).expect("plan");
        let ids = CanaryIds::from_plan(&plan, epoch).expect("ids");
        (rotation, ids)
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tpt-canary-ids-{name}-{}", std::process::id()))
    }

    #[test]
    fn text_round_trips_and_keeps_the_epoch() {
        let (_, ids) = ids();
        let parsed = CanaryIds::parse(&ids.to_text()).expect("parse");
        assert_eq!(parsed, ids);
        assert_eq!(parsed.epoch(), 40);
        assert_eq!(parsed.entries().len(), 3 * VaultId::ALL.len());
    }

    #[test]
    fn a_detector_from_the_list_matches_the_plan_detector() {
        let (rotation, ids) = ids();
        let plan = rotation.plan_at(NOW).expect("plan");
        let from_plan = Detector::new(&plan).expect("detector");
        let from_list = Detector::from_entries(ids.entries());
        let queries: Vec<_> = ids
            .entries()
            .iter()
            .map(|(vault, _, id)| (*vault, id.clone()))
            .collect();
        assert_eq!(from_plan.scan(&queries), from_list.scan(&queries));
        assert_eq!(from_list.scan(&queries).len(), queries.len());
    }

    #[test]
    fn malformed_lists_are_refused() {
        let (_, ids) = ids();
        let good = ids.to_text();
        let bad_header = good.replacen(HEADER, "something else", 1);
        let bad_epoch = good.replacen("epoch 40", "epoch forty", 1);
        let bad_vault = good.replacen("\nA ", "\nZ ", 1);
        let bad_hex = good.replacen(&hex(ids.entries()[0].2.as_bytes()), "zz", 1);
        let extra_field = good.replacen("\nA 0 ", "\nA 0 extra ", 1);
        let empty = format!("{HEADER}\nepoch 40\n");
        for text in [
            bad_header,
            bad_epoch,
            bad_vault,
            bad_hex,
            extra_field,
            empty,
        ] {
            assert!(CanaryIds::parse(&text).is_err(), "accepted: {text}");
        }
    }

    #[test]
    fn a_written_file_reads_back() {
        let (_, ids) = ids();
        let path = temp_path("round-trip");
        ids.write_file(&path).expect("write");
        let read = CanaryIds::read_file(&path).expect("read");
        let _ = fs::remove_file(&path);
        assert_eq!(read, ids);
    }
}
