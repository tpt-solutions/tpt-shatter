// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The audit chain on disk: one JSON line per record, synced before a call returns.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::audit::{AuditChain, AuditEvent, AuditRecord, verify_chain};
use crate::error::ShatterError;

/// The audit chain on disk. Every record is verified on open, and the chain resumes from
/// its last record.
pub struct AuditStore {
    state: Mutex<AuditState>,
    key: [u8; 32],
}

struct AuditState {
    chain: AuditChain,
    file: File,
    /// Set after a failed write. The in-memory chain is then ahead of the file, so no
    /// further record is accepted until the process restarts and reloads from the file.
    broken: bool,
}

impl AuditStore {
    /// Opens the log at `path`, verifies it under `key`, and resumes the chain.
    /// A log that fails verification refuses to open.
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, ShatterError> {
        let mut records = Vec::new();
        match File::open(path) {
            Ok(file) => {
                for line in BufReader::new(file).lines() {
                    let line = line.map_err(|_| ShatterError::Internal)?;
                    if !line.is_empty() {
                        records.push(AuditRecord::decode_line(&line)?);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ShatterError::Internal),
        }
        verify_chain(key, &records)?;
        let chain = AuditChain::resume(key, &records)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| ShatterError::Internal)?;
        Ok(Self {
            state: Mutex::new(AuditState {
                chain,
                file,
                broken: false,
            }),
            key,
        })
    }

    /// Appends one event and syncs it to disk before returning.
    pub fn record(&self, event: AuditEvent) -> Result<(), ShatterError> {
        let mut state = self.state.lock().map_err(|_| ShatterError::Internal)?;
        if state.broken {
            return Err(ShatterError::Internal);
        }
        let record = state.chain.append(event)?;
        let mut line = record.encode_line();
        line.push('\n');
        let written = state
            .file
            .write_all(line.as_bytes())
            .and_then(|()| state.file.sync_data());
        if written.is_err() {
            state.broken = true;
            return Err(ShatterError::Internal);
        }
        Ok(())
    }

    /// The key the chain is verified under.
    #[must_use]
    pub const fn key(&self) -> &[u8; 32] {
        &self.key
    }
}
