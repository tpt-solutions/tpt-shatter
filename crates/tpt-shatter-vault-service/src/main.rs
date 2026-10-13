// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `tpt-shatter-vault <config.json>`: serves one vault over mTLS until stopped.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tpt_shatter_common::{RetentionPolicy, VaultId};
use tpt_shatter_vault_client::{FileVault, VaultBackend};
use tpt_shatter_vault_service::{read_key_file, serve, server_tls};

/// One vault's configuration. Unknown fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultConfig {
    /// Address to listen on, for example `0.0.0.0:7443`.
    listen: String,
    /// Server certificate chain (PEM).
    tls_cert: PathBuf,
    /// Server private key (PEM).
    tls_key: PathBuf,
    /// CA that node certificates must chain to. Clients without one are refused.
    client_ca: PathBuf,
    /// The vault label, `A`, `B`, or `C`.
    vault: String,
    /// Directory holding this vault's fragment files.
    dir: PathBuf,
    /// File holding this vault's sealing key (64 hex characters, mode 0400).
    key_file: PathBuf,
    /// How long fragments are kept, in seconds.
    retention_secs: u64,
    /// Seconds between retention purges.
    purge_interval_secs: u64,
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: tpt-shatter-vault <config.json>");
        return ExitCode::FAILURE;
    };
    match run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tpt-shatter-vault: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(config_path).map_err(|_| "config: unreadable".to_owned())?;
    let config: VaultConfig = serde_json::from_str(&text).map_err(|e| format!("config: {e}"))?;
    if config.purge_interval_secs == 0 {
        return Err("config: purge_interval_secs must be positive".to_owned());
    }
    let label = config
        .vault
        .chars()
        .next()
        .ok_or("config: vault label is empty")?;
    let vault = VaultId::from_label(label).map_err(|_| "config: unknown vault label".to_owned())?;
    let retention = RetentionPolicy::new(config.retention_secs)
        .map_err(|_| "config: retention_secs must be positive".to_owned())?;

    let key = read_key_file(&config.key_file).map_err(|_| "key file: refused".to_owned())?;
    let store = Arc::new(
        FileVault::open(vault, &config.dir, &key).map_err(|e| format!("open vault: {e}"))?,
    );
    let tls = server_tls(
        &fs::read(&config.tls_cert).map_err(|_| "tls_cert: unreadable".to_owned())?,
        &fs::read(&config.tls_key).map_err(|_| "tls_key: unreadable".to_owned())?,
        &fs::read(&config.client_ca).map_err(|_| "client_ca: unreadable".to_owned())?,
    )
    .map_err(|e| format!("tls: {e}"))?;

    let purger = Arc::clone(&store);
    let interval = Duration::from_secs(config.purge_interval_secs);
    thread::spawn(move || {
        loop {
            thread::sleep(interval);
            match purger.purge_expired(retention, now_secs()) {
                Ok(report) => eprintln!("retention pass: {report:?}"),
                Err(e) => eprintln!("retention pass failed: {e}"),
            }
        }
    });

    let listener = TcpListener::bind(&config.listen).map_err(|e| format!("listen: {e}"))?;
    eprintln!("tpt-shatter-vault serving vault {label}");
    let backend: Arc<dyn VaultBackend> = store;
    serve(listener, tls, backend).map_err(|e| format!("serve: {e}"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
