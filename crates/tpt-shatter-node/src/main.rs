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
use tpt_shatter_node::{Config, Keys, Node, Source, load_config, now_secs};
use tpt_shatter_shredder::run_reaper;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tpt-shatter-node: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: tpt-shatter-node <config.json>")?;
    let config = load_config(Path::new(&path)).map_err(|e| format!("config: {e}"))?;
    let keys = Keys::from_lookup(|name| env::var(name).ok())
        .map_err(|e| format!("keys: {e} (set every TPT_KEY_* variable to 64 hex characters)"))?;
    let acceptor = tls_acceptor(&config)?;

    let node = Node::build(config.clone(), keys).map_err(|e| format!("build: {e}"))?;
    node.refresh_canaries(now_secs())
        .map_err(|e| format!("canaries: {e}"))?;

    let access_log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|line: &str| eprintln!("{line}"));
    let shared = Arc::new(
        node.shared(access_log)
            .map_err(|e| format!("gateway: {e}"))?,
    );
    let shredder = node.shredder();
    let reap_alerts = node.alert_log().map_err(|e| format!("alert log: {e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;

    // The issuer runs on its own listener, next to the read path, with the same TLS rules.
    if let (Some(issuer), Some(issuer_config)) = (node.issuer(), config.issuer.as_ref()) {
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind(&issuer_config.listen))
            .map_err(|e| format!("issuer listen: {e}"))?;
        eprintln!("issuer listening on {}", issuer_config.listen);
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
                        eprintln!("reaper: abandoned {} orphan(s); escalate", report.abandoned);
                    }
                },
            );
            if let Err(e) = result {
                eprintln!("reaper stopped: {e}");
            }
        });
        scope.spawn(|| monitor_loop(&node, monitor_interval, &stop));
        scope.spawn(|| purge_loop(&node, purge_interval, &stop));
        runtime.block_on(serve_http(&config, shared, acceptor))
    })
}

/// Erases expired fragments once per interval, until stopped. Logs counts only.
fn purge_loop(node: &Node, interval: Duration, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match node.purge_expired(now_secs()) {
            Ok(report) if report.purged > 0 || report.malformed > 0 => {
                eprintln!(
                    "retention: purged {} expired fragment(s); {} file(s) did not authenticate",
                    report.purged, report.malformed
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("retention purge failed: {e}"),
        }
        thread::sleep(interval);
    }
}

/// Canary refresh, then the alarm response, once per interval, until stopped.
fn monitor_loop(node: &Node, interval: Duration, stop: &AtomicBool) {
    let mut monitor = match node.monitor() {
        Ok(monitor) => monitor,
        Err(e) => {
            eprintln!("monitor: {e}");
            return;
        }
    };
    let responder = node.responder();
    while !stop.load(Ordering::SeqCst) {
        let now = now_secs();
        if let Err(e) = node.refresh_canaries(now) {
            eprintln!("canary refresh failed: {e}");
        }
        match monitor.poll(&responder, now) {
            Ok(Outcome::Fired { alarms }) => {
                eprintln!("canary alarm: responded to {alarms} alarm(s)");
            }
            Ok(Outcome::Suppressed { alarms }) => {
                eprintln!("canary alarm: {alarms} alarm(s) while disarmed; re-arm after cooldown");
            }
            Ok(Outcome::Quiet) => {}
            Err(e) => eprintln!("alarm response failed: {e}"),
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
    eprintln!("listening on {address} ({scheme})");
    let result = match acceptor {
        Some(acceptor) => serve_tls(listener, shared, acceptor).await,
        None => serve(listener, shared).await,
    };
    result.map_err(|e| format!("server: {e}"))
}
