// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Runs one tpt-shatter node from a configuration file.
//!
//! Usage: `tpt-shatter-node <config.json>`
//!
//! Keys come from the environment (see `tpt_shatter_node::KEY_VARS`). The process runs
//! four things at once: the HTTP read path, the orphan reaper, the canary monitor, and
//! the retention purge.
//! It stops on a fatal error or when the process is killed.
//!
//! Logs go to stderr as one JSON object per line, through `tracing`. Events carry counts
//! and status codes, never values, tokens, or shard keys (see `DECISIONS.md`, Observability).

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tpt_shatter_canary::Outcome;
use tpt_shatter_gateway::{Shared, acceptor, serve, serve_tls, server_config};
use tpt_shatter_node::{
    Config, Keys, Node, Source, access_log_sink, export_analytics, export_audit, init_logging,
    load_config, now_secs, serve_metrics,
};
use tpt_shatter_shredder::run_reaper;
use tracing::{error, info, warn};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!(%message, "node stopped");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    init_logging();
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("export-analytics") {
        return run_export(&args[2..]);
    }
    if args.get(1).map(String::as_str) == Some("export-audit") {
        return run_export_audit(&args[2..]);
    }
    let path = args.get(1).ok_or(
        "usage: tpt-shatter-node <config.json> | export-analytics <config.json> <group> [value] | export-audit <config.json>",
    )?;
    let config = load_config(Path::new(&path)).map_err(|e| format!("config: {e}"))?;
    let keys = load_keys().map_err(|e| {
        format!("keys: {e} (set TPT_KEYS_DIR, or every TPT_KEY_* variable to 64 hex characters)")
    })?;
    let acceptor = tls_acceptor(&config)?;

    let node = Node::build(config.clone(), keys).map_err(|e| format!("build: {e}"))?;
    node.refresh_canaries(now_secs())
        .map_err(|e| format!("canaries: {e}"))?;

    let shared = Arc::new(
        node.shared(access_log_sink())
            .map_err(|e| format!("gateway: {e}"))?,
    );
    let shredder = node.shredder();
    let reap_alerts = node.alert_log().map_err(|e| format!("alert log: {e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;

    // The metrics endpoint runs on its own listener, on the management network.
    if let Some(address) = &config.metrics_listen {
        let listener = runtime
            .block_on(TcpListener::bind(address))
            .map_err(|e| format!("metrics listen: {e}"))?;
        info!(%address, "metrics listening");
        runtime.spawn(serve_metrics(
            listener,
            acceptor.clone(),
            node.metrics_renderer(),
        ));
    }

    // The issuer runs on its own listener, next to the read path, with the same TLS rules.
    if let (Some(issuer), Some(issuer_config)) = (node.issuer(), config.issuer.as_ref()) {
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind(&issuer_config.listen))
            .map_err(|e| format!("issuer listen: {e}"))?;
        info!(address = %issuer_config.listen, "issuer listening");
        runtime.spawn(tpt_shatter_node::serve_issuer(
            listener,
            acceptor.clone(),
            issuer,
        ));
    }

    let stop = AtomicBool::new(false);
    let reap_interval = Duration::from_secs(config.reap_interval_secs);
    let monitor_interval = Duration::from_secs(config.monitor_interval_secs);
    let purge_interval = Duration::from_secs(config.purge_interval_secs);
    let export_interval = Duration::from_secs(
        config
            .analytics
            .as_ref()
            .map_or(3600, |analytics| analytics.export_interval_secs),
    );

    thread::scope(|scope| {
        scope.spawn(|| {
            let result = run_reaper(
                &shredder,
                reap_interval,
                config.reap_max_attempts,
                &stop,
                Some(&reap_alerts),
                |report| {
                    if report.abandoned > 0 {
                        warn!(
                            abandoned = report.abandoned,
                            "reaper abandoned orphans; escalate"
                        );
                    }
                },
            );
            if let Err(e) = result {
                error!(error = %e, "reaper stopped");
            }
        });
        scope.spawn(|| monitor_loop(&node, monitor_interval, &stop));
        scope.spawn(|| purge_loop(&node, purge_interval, &stop));
        scope.spawn(|| export_loop(&node, export_interval, &stop));
        runtime.block_on(serve_http(&config, shared, acceptor))
    })
}

/// Loads the keys from `TPT_KEYS_DIR` when it is set (production), or else from the
/// `TPT_KEY_*` environment variables (development only).
fn load_keys() -> Result<Keys, tpt_shatter_common::ShatterError> {
    match env::var_os("TPT_KEYS_DIR") {
        Some(dir) => Keys::from_dir(Path::new(&dir)),
        None => Keys::from_lookup(|name| env::var(name).ok()),
    }
}

/// `export-analytics <config.json> <group> [value]`: writes the analytics CSV to stdout.
/// It reads the analytics log only, so it is safe while the node is running.
fn run_export(args: &[String]) -> Result<(), String> {
    const USAGE: &str = "usage: tpt-shatter-node export-analytics <config.json> <group> [value]";
    let [config_path, group, rest @ ..] = args else {
        return Err(USAGE.to_owned());
    };
    let config = load_config(Path::new(config_path)).map_err(|e| format!("config: {e}"))?;
    let keys = load_keys().map_err(|e| format!("keys: {e}"))?;
    let csv = export_analytics(&config, &keys, group, rest.first().map(String::as_str))
        .map_err(|e| format!("export: {e}"))?;
    print!("{csv}");
    Ok(())
}

/// `export-audit <config.json>`: writes the audit compliance summary to stdout as JSON.
/// It verifies the chain under the audit key and reads the log only, so it is safe while
/// the node is running.
fn run_export_audit(args: &[String]) -> Result<(), String> {
    const USAGE: &str = "usage: tpt-shatter-node export-audit <config.json>";
    let [config_path] = args else {
        return Err(USAGE.to_owned());
    };
    let config = load_config(Path::new(config_path)).map_err(|e| format!("config: {e}"))?;
    let keys = load_keys().map_err(|e| format!("keys: {e}"))?;
    let json = export_audit(&config, &keys).map_err(|e| format!("export: {e}"))?;
    println!("{json}");
    Ok(())
}

/// Writes the scheduled analytics exports once per interval, until stopped. Does nothing
/// when the config has no exports. Logs counts only.
fn export_loop(node: &Node, interval: Duration, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match node.write_analytics_exports(now_secs()) {
            Ok(0) => {}
            Ok(written) => info!(written, "analytics exports written"),
            Err(e) => error!(error = %e, "analytics export failed"),
        }
        thread::sleep(interval);
    }
}

/// Erases expired fragments and analytics events once per interval, until stopped.
/// Logs counts only.
fn purge_loop(node: &Node, interval: Duration, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        let now = now_secs();
        match node.purge_expired(now) {
            Ok(report) if report.purged > 0 || report.malformed > 0 => {
                info!(
                    purged = report.purged,
                    malformed = report.malformed,
                    "retention purge ran"
                );
            }
            Ok(_) => {}
            Err(e) => error!(error = %e, "retention purge failed"),
        }
        match node.purge_analytics(now) {
            Ok(0) => {}
            Ok(erased) => info!(erased, "analytics events expired"),
            Err(e) => error!(error = %e, "analytics purge failed"),
        }
        thread::sleep(interval);
    }
}

/// Canary refresh, then the alarm response, once per interval, until stopped.
fn monitor_loop(node: &Node, interval: Duration, stop: &AtomicBool) {
    let mut monitor = match node.monitor() {
        Ok(monitor) => monitor,
        Err(e) => {
            error!(error = %e, "canary monitor failed to start");
            return;
        }
    };
    let responder = node.responder();
    while !stop.load(Ordering::SeqCst) {
        let now = now_secs();
        if let Err(e) = node.refresh_canaries(now) {
            error!(error = %e, "canary refresh failed");
        }
        if let Err(e) = node.push_canary_ids() {
            error!(error = %e, "canary list push failed");
        }
        match monitor.poll(&responder, now) {
            Ok(Outcome::Fired { alarms }) => {
                warn!(alarms, "canary alarm responded");
            }
            Ok(Outcome::Suppressed { alarms }) => {
                warn!(
                    alarms,
                    "canary alarm suppressed while disarmed; re-arm after cooldown"
                );
            }
            Ok(Outcome::Quiet) => {}
            Err(e) => error!(error = %e, "alarm response failed"),
        }
        match node.flush_analytics(now) {
            Ok(0) => {}
            Ok(emitted) => info!(emitted, "analytics events emitted"),
            Err(e) => error!(error = %e, "analytics flush failed"),
        }
        thread::sleep(interval);
    }
}

/// Builds the TLS acceptor, or returns `None` when plain HTTP is allowed and no
/// certificate is configured. Plain HTTP is never the default.
fn tls_acceptor(config: &Config) -> Result<Option<TlsAcceptor>, String> {
    match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = fs::read(cert).map_err(|e| format!("tls_cert: {e}"))?;
            let key_pem = fs::read(key).map_err(|e| format!("tls_key: {e}"))?;
            let client_ca = config
                .client_ca
                .as_ref()
                .map(fs::read)
                .transpose()
                .map_err(|e| format!("client_ca: {e}"))?;
            let tls = server_config(&cert_pem, &key_pem, client_ca.as_deref())
                .map_err(|e| format!("tls: {e}"))?;
            Ok(Some(acceptor(tls)))
        }
        (None, None) if config.allow_plain_http => Ok(None),
        _ => Err(
            "tls_cert and tls_key are required (set allow_plain_http only for development)"
                .to_owned(),
        ),
    }
}

async fn serve_http(
    config: &Config,
    shared: Arc<Shared<Source>>,
    acceptor: Option<TlsAcceptor>,
) -> Result<(), String> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|e| format!("listen: {e}"))?;
    let address = listener.local_addr().map_err(|e| format!("listen: {e}"))?;
    let scheme = if acceptor.is_some() {
        "https"
    } else {
        "http (development only)"
    };
    info!(%address, scheme, "listening");
    let result = match acceptor {
        Some(acceptor) => serve_tls(listener, shared, acceptor).await,
        None => serve(listener, shared).await,
    };
    result.map_err(|e| format!("server: {e}"))
}
