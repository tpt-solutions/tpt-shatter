// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `tpt-shatter-assembler <config.json>`: serves the assembler over mTLS until stopped.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tpt_shatter_assembler_service::{
    AssemblerSource, CanaryWatcher, Freshness, LockedSource, ReadGate, serve, serve_canary_list,
};
use tpt_shatter_canary::{CanaryIds, CanaryWatch};
use tpt_shatter_common::{ShatterSchema, VaultId};
use tpt_shatter_gateway::RecordSource;
use tpt_shatter_gateway::server_config;
use tpt_shatter_vault_client::{
    AccessObserver, BreakerConfig, Guarded, Router, VaultBackend, system_clock,
};
use tpt_shatter_vault_service::{RemoteVault, client_tls_from_files, read_key_file};

/// The assembler's configuration. Unknown fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Address to listen on, for example `0.0.0.0:7444`.
    listen: String,
    /// The canary FragmentIds the node writes for the current epoch. Required: the assembler
    /// refuses to start without a readable list, so it never serves reads unwatched.
    canary_ids_file: PathBuf,
    /// The security alert log. Canary alarms and rejected canary lists are appended here.
    alert_log: PathBuf,
    /// Seconds between canary passes. Must be positive. Defaults to 30.
    #[serde(default = "default_monitor_secs")]
    monitor_interval_secs: u64,
    /// The node's canary rotation period, in seconds. Must match the node's
    /// `canary_period_secs`, or the staleness check is wrong.
    canary_period_secs: u64,
    /// Seconds past the end of an epoch before its canary list counts as stale. Covers the
    /// node's pass after a boundary. Defaults to 600.
    #[serde(default = "default_stale_grace_secs")]
    canary_stale_grace_secs: u64,
    /// Where the node pushes its canary list. Absent means the list is copied to
    /// `canary_ids_file` by hand, as before.
    #[serde(default)]
    canary_push: Option<CanaryPushConfig>,
    /// Server certificate chain (PEM).
    tls_cert: PathBuf,
    /// Server private key (PEM).
    tls_key: PathBuf,
    /// CA that the gateway's client certificate must chain to. Clients without one are refused.
    client_ca: PathBuf,
    /// The shatter schema, as JSON.
    schema: PathBuf,
    /// The derivation key: 64 hex characters, mode 0400 or 0600 on Unix.
    derivation_key_file: PathBuf,
    /// How long one reassembly may wait on the vaults, in seconds. Keep it below the
    /// gateway's request timeout. Defaults to 3.
    #[serde(default = "default_deadline_secs")]
    read_deadline_secs: u64,
    /// The three vault services this assembler reads from.
    remote_vaults: RemoteVaults,
}

/// The vault services, reached over mTLS with this assembler's client certificate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteVaults {
    /// `host:port` of vault A's service.
    a: String,
    /// `host:port` of vault B's service.
    b: String,
    /// `host:port` of vault C's service.
    c: String,
    /// Name the services' certificates must carry, used for every vault unless
    /// `server_names` is set.
    server_name: String,
    /// Per-vault certificate names, for services in separate namespaces.
    server_names: Option<ServerNames>,
    /// CA that the services' certificates must chain to (PEM).
    ca: PathBuf,
    /// This assembler's client certificate (PEM).
    client_cert: PathBuf,
    /// This assembler's client private key (PEM).
    client_key: PathBuf,
}

/// The certificate name each vault service must present.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerNames {
    a: String,
    b: String,
    c: String,
}

fn default_deadline_secs() -> u64 {
    3
}

/// The listener that accepts canary list pushes from the node.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanaryPushConfig {
    /// Address to listen on, for example `0.0.0.0:7445`. Keep it off the gateway's network.
    listen: String,
    /// CA that the node's client certificate must chain to. Separate from the gateway's CA.
    client_ca: PathBuf,
}

fn default_monitor_secs() -> u64 {
    30
}

fn default_stale_grace_secs() -> u64 {
    600
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: tpt-shatter-assembler <config.json>");
        return ExitCode::FAILURE;
    };
    match run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tpt-shatter-assembler: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(config_path).map_err(|_| "config: unreadable".to_owned())?;
    let config: Config = serde_json::from_str(&text).map_err(|e| format!("config: {e}"))?;
    if config.read_deadline_secs == 0
        || config.monitor_interval_secs == 0
        || config.canary_period_secs == 0
    {
        return Err("config: deadlines and intervals must be positive".to_owned());
    }

    let schema =
        ShatterSchema::load_json_file(&config.schema).map_err(|_| "schema: refused".to_owned())?;
    let derivation = read_key_file(&config.derivation_key_file)
        .map_err(|_| "derivation key: refused".to_owned())?;
    // With no list on disk yet, start awaiting the node's first push and refuse reads until it
    // arrives. A list that is present but unreadable still refuses to start.
    let awaiting = !config.canary_ids_file.exists();
    let ids = if awaiting {
        None
    } else {
        Some(
            CanaryIds::read_file(&config.canary_ids_file)
                .map_err(|_| "canary ids: refused".to_owned())?,
        )
    };
    let watch = Arc::new(match &ids {
        Some(ids) => CanaryWatch::from_ids(ids),
        None => CanaryWatch::unwatched(),
    });
    let gate = Arc::new(ReadGate::new(awaiting));

    let vaults = &config.remote_vaults;
    let client_tls = client_tls_from_files(&vaults.ca, &vaults.client_cert, &vaults.client_key)
        .map_err(|_| "vault client identity: refused".to_owned())?;
    let names = match &vaults.server_names {
        Some(n) => [n.a.clone(), n.b.clone(), n.c.clone()],
        None => std::array::from_fn(|_| vaults.server_name.clone()),
    };
    let mut guards = Vec::with_capacity(3);
    for ((vault, addr), name) in [
        (VaultId::A, &vaults.a),
        (VaultId::B, &vaults.b),
        (VaultId::C, &vaults.c),
    ]
    .into_iter()
    .zip(names)
    {
        let backend: Box<dyn VaultBackend> = Box::new(
            RemoteVault::new(vault, addr, &name, Arc::clone(&client_tls))
                .map_err(|_| "vault service: refused".to_owned())?,
        );
        guards.push(Guarded::new(
            backend,
            BreakerConfig::default(),
            system_clock(),
        ));
    }
    // The watch sees every read this router makes, including the ones the assembler makes
    // for its own reassembly.
    let observer: Arc<dyn AccessObserver> = Arc::clone(&watch) as Arc<dyn AccessObserver>;
    let router = Arc::new(
        Router::new(guards)
            .map_err(|_| "router: refused".to_owned())?
            .with_observer(observer),
    );

    let inner: Arc<dyn RecordSource> = Arc::new(AssemblerSource::new(
        Arc::new(schema),
        router,
        derivation,
        Duration::from_secs(config.read_deadline_secs),
    ));
    let source = Arc::new(LockedSource::new(inner, Arc::clone(&gate)));

    let mut watcher = CanaryWatcher::new(
        config.canary_ids_file.clone(),
        ids.as_ref(),
        Arc::clone(&watch),
        &config.alert_log,
        Arc::clone(&gate),
        Freshness {
            period_secs: config.canary_period_secs,
            grace_secs: config.canary_stale_grace_secs,
        },
    )
    .map_err(|_| "alert log or canary period: refused".to_owned())?;
    let interval = Duration::from_secs(config.monitor_interval_secs);
    thread::spawn(move || {
        loop {
            if let Err(e) = watcher.pass(now_secs()) {
                eprintln!("tpt-shatter-assembler: canary pass: {e}");
            }
            thread::sleep(interval);
        }
    });

    let tls = server_config(
        &fs::read(&config.tls_cert).map_err(|_| "tls_cert: unreadable".to_owned())?,
        &fs::read(&config.tls_key).map_err(|_| "tls_key: unreadable".to_owned())?,
        Some(&fs::read(&config.client_ca).map_err(|_| "client_ca: unreadable".to_owned())?),
    )
    .map_err(|_| "tls: refused".to_owned())?;

    if let Some(push) = &config.canary_push {
        // The list listener accepts only the node, so it uses the node's CA, not the gateway's.
        let push_tls = server_config(
            &fs::read(&config.tls_cert).map_err(|_| "tls_cert: unreadable".to_owned())?,
            &fs::read(&config.tls_key).map_err(|_| "tls_key: unreadable".to_owned())?,
            Some(
                &fs::read(&push.client_ca)
                    .map_err(|_| "canary client_ca: unreadable".to_owned())?,
            ),
        )
        .map_err(|_| "canary tls: refused".to_owned())?;
        let push_listener =
            TcpListener::bind(&push.listen).map_err(|e| format!("canary listen: {e}"))?;
        let list = config.canary_ids_file.clone();
        thread::spawn(move || {
            if let Err(e) = serve_canary_list(push_listener, push_tls, list) {
                eprintln!("tpt-shatter-assembler: canary list listener stopped: {e}");
            }
        });
    }

    let listener = TcpListener::bind(&config.listen).map_err(|e| format!("listen: {e}"))?;
    serve(listener, tls, source).map_err(|_| "server stopped".to_owned())
}
