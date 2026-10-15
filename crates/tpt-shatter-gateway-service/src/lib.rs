// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The gateway as its own process.
//!
//! The gateway checks tokens, applies rate limits, records each authorized read, and asks
//! the assembler service for the record over mTLS. It holds the token key and its own audit
//! key. It holds no derivation key, no vault key, and no vault client.
//!
//! Canary alarms reach this process through the alarm listener. The node pushes a new token
//! signing key there, over mTLS, when its canary monitor fires, so a canary read revokes the
//! tokens here too. A gateway without an alarm listener cannot be told about canary alarms,
//! so its config refuses to start unless it sets `acknowledge_canary_gap: true`. See
//! `DECISIONS.md`, "Canary alarm propagation".

pub mod alarm;

use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::Deserialize;
use tpt_shatter_common::{
    AUDIT_DIGEST_LEN, AuditAction, AuditEvent, AuditStore, CALLER_TAG_LEN, Scope, ShardKey,
    ShatterError, keyed_digest, read_key_file,
};
use tpt_shatter_gateway::remote::client_config;
use tpt_shatter_gateway::{
    AccessAudit, Gateway, HttpConfig, RateLimiter, RemoteAssembler, Shared, acceptor, serve_tls,
    server_config,
};
use tpt_shatter_token::Signer;

pub use alarm::serve_alarms;

/// The audit chain this gateway writes. It is separate from the node's chain, so the node's
/// audit key is never needed here.
pub const AUDIT_LOG: &str = "gateway-audit.jsonl";

/// The token key version the node issues under. Tokens carry it, and the signer checks it.
pub const TOKEN_KEY_VERSION: u32 = 1;

/// Records authorized reads on this gateway's audit chain. Writes are not served here, so
/// a write scope is refused before anything is recorded.
pub struct GatewayAudit {
    store: Arc<AuditStore>,
}

impl GatewayAudit {
    /// Records to `store`.
    #[must_use]
    pub const fn new(store: Arc<AuditStore>) -> Self {
        Self { store }
    }
}

impl AccessAudit for GatewayAudit {
    fn authorized(
        &self,
        scope: Scope,
        token: &str,
        caller: &[u8; CALLER_TAG_LEN],
        shard: &ShardKey,
        now: u64,
    ) -> Result<(), ShatterError> {
        if scope != Scope::Read {
            return Err(ShatterError::InvalidParameter);
        }
        let key = self.store.key();
        self.store.record(AuditEvent {
            action: AuditAction::Read,
            token_digest: keyed_digest(key, b"tpt-shatter/read/token", token.as_bytes())?,
            shard_digest: keyed_digest(key, b"tpt-shatter/read/shard", shard.as_bytes())?,
            caller: caller_digest(key, caller)?,
            vault: None,
            at: now,
        })
    }
}

/// The digest of a caller tag. A token issued without a caller (all zeros) has none.
fn caller_digest(
    key: &[u8; 32],
    caller: &[u8; CALLER_TAG_LEN],
) -> Result<Option<[u8; AUDIT_DIGEST_LEN]>, ShatterError> {
    if caller == &[0; CALLER_TAG_LEN] {
        return Ok(None);
    }
    keyed_digest(key, b"tpt-shatter/caller", caller).map(Some)
}

/// The gateway's configuration. Unknown fields are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Address to listen on, for example `0.0.0.0:8443`.
    pub listen: String,
    /// Server certificate chain (PEM).
    pub tls_cert: PathBuf,
    /// Server private key (PEM).
    pub tls_key: PathBuf,
    /// CA that client certificates must chain to. Without it, clients present tokens only.
    pub client_ca: Option<PathBuf>,
    /// Directory holding the gateway's audit chain.
    pub state_dir: PathBuf,
    /// The token signing key: 64 hex characters, mode 0400 or 0600 on Unix.
    pub token_key_file: PathBuf,
    /// This gateway's audit key: 64 hex characters, mode 0400 or 0600 on Unix. Not the node's.
    pub audit_key_file: PathBuf,
    /// Set to `true` only when there is no alarm listener and the operator accepts that canary
    /// alarms do not reach this gateway. Ignored when `alarm` is set.
    #[serde(default)]
    pub acknowledge_canary_gap: bool,
    /// The alarm listener, through which the node pushes new signing keys. Absent means canary
    /// alarms do not reach this gateway.
    #[serde(default)]
    pub alarm: Option<AlarmListener>,
    /// The assembler service this gateway reads through.
    pub assembler: AssemblerLink,
}

/// Where the node pushes signing-key rotations, and whom it accepts them from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlarmListener {
    /// Address to listen on, for example `0.0.0.0:7445`. Keep it on the management network.
    pub listen: String,
    /// CA that the node's client certificate must chain to. Other clients are refused.
    pub client_ca: PathBuf,
}

/// Where the assembler service is, and how this gateway proves who it is.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblerLink {
    /// `host:port` of the assembler service.
    pub addr: String,
    /// Name the assembler's certificate must carry.
    pub server_name: String,
    /// CA that the assembler's certificate must chain to (PEM).
    pub ca: PathBuf,
    /// This gateway's client certificate (PEM).
    pub client_cert: PathBuf,
    /// This gateway's client private key (PEM).
    pub client_key: PathBuf,
    /// How long one assembler call may take, in seconds. Defaults to 5.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

const fn default_timeout_secs() -> u64 {
    5
}

impl GatewayConfig {
    /// Parses a configuration from JSON.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Refuses a configuration that is unsafe to start with.
    pub fn validate(&self) -> Result<(), String> {
        if self.alarm.is_none() && !self.acknowledge_canary_gap {
            return Err(
                "config: set alarm, or set acknowledge_canary_gap to true; without an alarm listener, canary alarms do not revoke tokens on this gateway"
                    .to_owned(),
            );
        }
        if self.assembler.timeout_secs == 0 {
            return Err("config: assembler.timeout_secs must be positive".to_owned());
        }
        Ok(())
    }
}

/// Starts the gateway as configured and serves until the read listener fails.
pub fn run(config: &GatewayConfig) -> Result<(), String> {
    let token_key = read_key_file(&config.token_key_file).map_err(|_| "token key: refused")?;
    let audit_key = read_key_file(&config.audit_key_file).map_err(|_| "audit key: refused")?;
    let audit = Arc::new(
        AuditStore::open(&config.state_dir.join(AUDIT_LOG), audit_key)
            .map_err(|_| "audit log: refused".to_owned())?,
    );

    let signer = Arc::new(RwLock::new(Signer::new(TOKEN_KEY_VERSION, token_key)));

    // The alarm listener binds first, so a bad address is reported before anything serves.
    let server_cert = read(&config.tls_cert)?;
    let server_key = read(&config.tls_key)?;
    if let Some(alarm) = &config.alarm {
        let listener =
            StdTcpListener::bind(&alarm.listen).map_err(|e| format!("alarm listen: {e}"))?;
        let client_ca = read(&alarm.client_ca)?;
        let tls = server_config(&server_cert, &server_key, Some(&client_ca))
            .map_err(|_| "alarm tls: refused".to_owned())?;
        let (signer, audit) = (Arc::clone(&signer), Arc::clone(&audit));
        std::thread::spawn(move || {
            let _ = serve_alarms(listener, tls, signer, audit);
        });
    }

    let link = &config.assembler;
    let ca = read(&link.ca)?;
    let cert = read(&link.client_cert)?;
    let key = read(&link.client_key)?;
    let assembler_tls = client_config(&ca, Some((&cert, &key)))
        .map_err(|_| "assembler client identity: refused".to_owned())?;
    let source = RemoteAssembler::new(
        &link.addr,
        &link.server_name,
        assembler_tls,
        Duration::from_secs(link.timeout_secs),
    )
    .map_err(|_| "assembler address: refused".to_owned())?;

    let limiter =
        RateLimiter::new(10, 2, 10_000).map_err(|_| "rate limiter: refused".to_owned())?;
    let source_limiter =
        RateLimiter::new(20, 5, 10_000).map_err(|_| "rate limiter: refused".to_owned())?;
    let gateway = Arc::new(
        Gateway::new(Arc::clone(&signer), source, limiter)
            .with_audit(Arc::new(GatewayAudit::new(Arc::clone(&audit)))),
    );

    let client_ca = match &config.client_ca {
        Some(path) => Some(read(path)?),
        None => None,
    };
    let tls = server_config(&server_cert, &server_key, client_ca.as_deref())
        .map_err(|_| "tls: refused".to_owned())?;

    let shared = Arc::new(Shared {
        gateway,
        // No vault breakers exist in this process, so readiness reports only that it is up.
        // Assembler health is not part of readiness yet.
        breakers: Arc::new(Vec::<bool>::new),
        access_log: Arc::new(|line: &str| eprintln!("{line}")),
        config: HttpConfig::default(),
        source_limiter: Some(Mutex::new(source_limiter)),
        writer: None,
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime: refused".to_owned())?;
    runtime.block_on(async {
        let std_listener =
            StdTcpListener::bind(&config.listen).map_err(|e| format!("listen: {e}"))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("listen: {e}"))?;
        let listener =
            tokio::net::TcpListener::from_std(std_listener).map_err(|e| format!("listen: {e}"))?;
        serve_tls(listener, shared, acceptor(tls))
            .await
            .map_err(|e| format!("server stopped: {e}"))
    })
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|_| format!("{}: unreadable", path.display()))
}
