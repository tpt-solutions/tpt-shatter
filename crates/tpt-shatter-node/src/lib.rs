// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The tpt-shatter node: wires the vault store, the router, canaries, the gateway, and
//! the background work into one process.
//!
//! What a node does:
//! - opens the three `FileVault` directories and routes all access through one `Router`;
//! - keeps the canaries for the current epoch in the vaults, and watches the router for
//!   any read or delete of one;
//! - serves the read path over HTTP (TLS by default);
//! - reaps orphan fragments and runs the canary response on a timer.
//!
//! What a node does not do yet: ingest records (no write endpoint), issue tokens (an
//! upstream issuer is out of scope), or deliver keys (see [`Keys`]).
//!
//! The node keeps all of its state in its vault directories and its state directory.
//! Nothing in this crate writes a key or a field value to disk.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::Deserialize;
use tpt_shatter_assembler::assemble_with_deadline;
use tpt_shatter_canary::{
    Alarm, CanaryIds, CanaryMonitor, CanaryRotation, CanaryWatch, refresh_canaries,
};
use tpt_shatter_common::{
    AlertLog, AuditRecord, Record, RetentionPolicy, ShardKey, ShatterError, ShatterSchema, VaultId,
    report,
};
use tpt_shatter_gateway::remote::{CanaryPeer, client_config};
use tpt_shatter_gateway::{
    AccessAudit, AlarmPeer, AlarmResponder, Gateway, HttpConfig, RateLimiter, RecordSink,
    RecordSource, Shared, SigningKeyRotator, WriteHandler, Writer,
};
use tpt_shatter_shredder::{EraseReport, OrphanStore, Shredder, erase};
use tpt_shatter_vault_service::{RemoteVault, client_tls_from_files};

use access_audit::NodeAudit;
pub use issuer::{AuditStore, IssueOutcome, Issuer, IssuerConfig, serve_issuer};
mod access_audit;
mod analytics;
mod issuer;

use analytics::{Analytics, ExportPlan, load_policy};
use tpt_shatter_token::Signer;
use tpt_shatter_vault_client::{
    AccessObserver, BreakerConfig, BreakerState, FileVault, Guarded, PurgeReport, Router,
    VaultBackend, system_clock,
};

/// File names inside the state directory.
const ORPHAN_LOG: &str = "orphans.jsonl";
const AUDIT_LOG: &str = "audit.jsonl";
const ALERT_LOG: &str = "alerts.jsonl";
const ANALYTICS_LOG: &str = "analytics.jsonl";
const CANARY_EPOCH: &str = "canary_epoch";
/// The current epoch's canary FragmentIds, for a split assembler to watch.
pub const CANARY_IDS: &str = "canary-ids.txt";

/// The analytics feed. Off unless the config names a policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsConfig {
    /// The anonymization policy (JSON). See `analytics.rs` for the format. Its events are kept
    /// for `retention_secs`, the same window as vault fragments.
    pub policy: PathBuf,
    /// Directory the scheduled exports are written into. Required when `exports` is not empty.
    #[serde(default)]
    pub export_dir: Option<PathBuf>,
    /// CSV exports to write on each export pass. Empty means no scheduled exports.
    #[serde(default)]
    pub exports: Vec<ExportConfig>,
    /// Seconds between export passes. Must be positive.
    #[serde(default = "default_export_interval_secs")]
    pub export_interval_secs: u64,
}

fn default_export_interval_secs() -> u64 {
    3600
}

/// One scheduled CSV export. See [`export_analytics`] for what it contains.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    /// The field to group by.
    pub group: String,
    /// The field to sum per group. Absent means count the events per group.
    #[serde(default)]
    pub value: Option<String>,
    /// File name inside `export_dir`. A plain name, not a path.
    pub file: String,
}

/// Remote vault services (`tpt-shatter-vault`), one per vault, reached over mTLS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVaults {
    /// `host:port` of vault A's service.
    pub a: String,
    /// `host:port` of vault B's service.
    pub b: String,
    /// `host:port` of vault C's service.
    pub c: String,
    /// Name the services' certificates must carry, for example `vault.internal`. Used for
    /// every vault unless `server_names` is set.
    pub server_name: String,
    /// Per-vault certificate names. Set this when each service runs under its own name, as
    /// in separate namespaces. When set, it replaces `server_name` for every vault.
    #[serde(default)]
    pub server_names: Option<VaultServerNames>,
    /// CA that the services' certificates must chain to (PEM).
    pub ca: PathBuf,
    /// This node's client certificate (PEM).
    pub client_cert: PathBuf,
    /// This node's client private key (PEM).
    pub client_key: PathBuf,
}

/// The certificate name each remote vault service must present.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultServerNames {
    /// Name for vault A's service certificate.
    pub a: String,
    /// Name for vault B's service certificate.
    pub b: String,
    /// Name for vault C's service certificate.
    pub c: String,
}

/// Where each vault keeps its files.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDirs {
    /// Directory for vault A (identity).
    pub a: PathBuf,
    /// Directory for vault B (demographic).
    pub b: PathBuf,
    /// Directory for vault C (financial and sensitive).
    pub c: PathBuf,
}

/// The node's configuration, read from a JSON file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on, for example `127.0.0.1:8443`.
    pub listen: String,
    /// Server certificate chain (PEM). Required unless `allow_plain_http` is set.
    pub tls_cert: Option<PathBuf>,
    /// Server private key (PEM).
    pub tls_key: Option<PathBuf>,
    /// CA that client certificates must chain to. Setting it turns on mTLS.
    pub client_ca: Option<PathBuf>,
    /// Serve plain HTTP. For local development only. Off by default.
    #[serde(default)]
    pub allow_plain_http: bool,
    /// The shatter schema (JSON).
    pub schema: PathBuf,
    /// Directory for the orphan log, the alert log, and the canary epoch marker.
    pub state_dir: PathBuf,
    /// The local vault directories. Required unless `remote_vaults` is set.
    #[serde(default)]
    pub vault_dirs: Option<VaultDirs>,
    /// Remote vault services, one per vault. When set, the node uses them in place of
    /// `vault_dirs` and needs no vault keys.
    #[serde(default)]
    pub remote_vaults: Option<RemoteVaults>,
    /// Canaries per epoch. Must be positive.
    pub canary_count: usize,
    /// Epoch length in seconds. Must be positive. A week is typical.
    pub canary_period_secs: u64,
    /// Seconds before the alarm gate can re-arm after a response.
    pub alarm_cooldown_secs: u64,
    /// Seconds between reap passes. Must be positive.
    pub reap_interval_secs: u64,
    /// Attempts an orphan gets before it is abandoned. Must be positive.
    pub reap_max_attempts: u32,
    /// Seconds between canary and alarm passes. Must be positive.
    pub monitor_interval_secs: u64,
    /// Maximum age of a stored fragment, in seconds. Fragments older than this are erased
    /// by the purge pass. Must be positive and at least `canary_period_secs`, so a canary
    /// is refreshed before its own retention runs out.
    pub retention_secs: u64,
    /// Seconds between retention purge passes. Must be positive. A pass reads and
    /// authenticates every fragment, so keep this coarser than the monitor interval.
    pub purge_interval_secs: u64,
    /// The token issuer. Absent means no issuer runs on this node.
    #[serde(default)]
    pub issuer: Option<IssuerConfig>,
    /// The analytics feed. Absent means accepted writes are not fed to analytics.
    #[serde(default)]
    pub analytics: Option<AnalyticsConfig>,
    /// Address for the Prometheus `/metrics` endpoint. Absent means no metrics listener.
    /// Put it on the management network. It uses the same TLS rules as the read path.
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// Where to push a new signing key after a canary alarm. Absent means the alarm rotates
    /// this node's key only, and gateways on other hosts are not told.
    #[serde(default)]
    pub gateway_alarm: Option<GatewayAlarm>,
    /// Where to push the canary list after each refresh. Absent means the list stays in the
    /// state directory, and must be copied to the assembler by hand.
    #[serde(default)]
    pub canary_push: Option<CanaryPush>,
}

/// The assembler's canary list listener, which receives the list after each refresh.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryPush {
    /// `host:port` of the assembler's canary list listener.
    pub addr: String,
    /// Name the listener's certificate must carry.
    pub server_name: String,
    /// CA that the assembler's certificate must chain to (PEM).
    pub ca: PathBuf,
    /// This node's client certificate, presented to the listener (PEM).
    pub client_cert: PathBuf,
    /// This node's client private key (PEM).
    pub client_key: PathBuf,
    /// Seconds one push may take. Defaults to 5.
    #[serde(default = "default_alarm_timeout_secs")]
    pub timeout_secs: u64,
}

/// The gateways that receive a new signing key when a canary alarm fires.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAlarm {
    /// One entry per gateway alarm listener.
    pub peers: Vec<AlarmPeerConfig>,
    /// CA that the gateways' alarm certificates must chain to (PEM).
    pub ca: PathBuf,
    /// This node's client certificate, presented to every peer (PEM).
    pub client_cert: PathBuf,
    /// This node's client private key (PEM).
    pub client_key: PathBuf,
    /// Seconds one push may take. Defaults to 5.
    #[serde(default = "default_alarm_timeout_secs")]
    pub timeout_secs: u64,
}

/// One gateway alarm listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlarmPeerConfig {
    /// `host:port` of the gateway's alarm listener.
    pub addr: String,
    /// Name the listener's certificate must carry.
    pub server_name: String,
}

const fn default_alarm_timeout_secs() -> u64 {
    5
}

/// Installs the JSON log subscriber on stderr at INFO and above. The binary calls this once
/// at start. Calling it again, or after another subscriber is set, does nothing.
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

pub use metrics::{Metrics, serve_metrics};
mod metrics;

/// The access log the binary installs: one structured `request` event per line.
#[must_use]
pub fn access_log_sink() -> Arc<dyn Fn(&str) + Send + Sync> {
    Arc::new(|line: &str| tracing::info!(access = line, "request"))
}

/// The eight 32-byte keys a node needs. Each is 64 hex characters in the environment.
///
/// Keys are read from the environment at boot and held in RAM. Key delivery from a
/// secret store is not built, so the environment is the interim source.
pub struct Keys {
    /// Sealing keys for the three local vaults. `None` when the vault keys are not
    /// provisioned on this node, which is the case when the node uses remote vault services.
    pub vaults: Option<VaultKeys>,
    /// FragmentId derivation key. Shared by the shredder and the assembler.
    pub derivation: [u8; 32],
    /// Token signing key, version 1.
    pub token: [u8; 32],
    /// Master key for canary derivation.
    pub canary_master: [u8; 32],
    /// Key the issuer's audit chain is verified and sealed under.
    pub audit: [u8; 32],
    /// Salt for pseudonyms in the analytics feed. Used even when analytics is off, so a
    /// node always has the same key set.
    pub analytics: [u8; 32],
}

/// The local vaults' sealing keys. Only a node that stores fragments itself holds these.
pub struct VaultKeys {
    /// Sealing key for vault A.
    pub a: [u8; 32],
    /// Sealing key for vault B.
    pub b: [u8; 32],
    /// Sealing key for vault C.
    pub c: [u8; 32],
}

/// Environment variable names for each key.
pub const KEY_VARS: [&str; 8] = [
    "TPT_KEY_VAULT_A",
    "TPT_KEY_VAULT_B",
    "TPT_KEY_VAULT_C",
    "TPT_KEY_DERIVATION",
    "TPT_KEY_TOKEN",
    "TPT_KEY_CANARY_MASTER",
    "TPT_KEY_AUDIT",
    "TPT_KEY_ANALYTICS",
];

impl Keys {
    /// Reads every key from a file in `dir`, one file per variable name, named as in
    /// [`KEY_VARS`]. Each file holds one key as 64 hex characters.
    ///
    /// This is the production source: the directory sits on a tmpfs, and the boot step
    /// writes it from the KMS-wrapped key material. On Unix, a file readable or writable by
    /// group or others is refused, so a key cannot be loaded from a shared-readable file.
    /// Errors name the variable, never its contents.
    pub fn from_dir(dir: &Path) -> Result<Self, ShatterError> {
        let get = |name: &str| -> Result<[u8; 32], ShatterError> {
            let path = dir.join(name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&path)
                    .map_err(|_| ShatterError::InvalidParameter)?
                    .permissions()
                    .mode();
                if mode & 0o077 != 0 {
                    return Err(ShatterError::InvalidParameter);
                }
            }
            let text = fs::read_to_string(&path).map_err(|_| ShatterError::InvalidParameter)?;
            parse_key(&text)
        };
        let present = |name: &str| dir.join(name).exists();
        let vaults = match (
            present(KEY_VARS[0]),
            present(KEY_VARS[1]),
            present(KEY_VARS[2]),
        ) {
            (false, false, false) => None,
            (true, true, true) => Some(VaultKeys {
                a: get(KEY_VARS[0])?,
                b: get(KEY_VARS[1])?,
                c: get(KEY_VARS[2])?,
            }),
            _ => return Err(ShatterError::InvalidParameter),
        };
        Ok(Self {
            vaults,
            derivation: get(KEY_VARS[3])?,
            token: get(KEY_VARS[4])?,
            canary_master: get(KEY_VARS[5])?,
            audit: get(KEY_VARS[6])?,
            analytics: get(KEY_VARS[7])?,
        })
    }

    /// Reads every key with `lookup`. Fails if any is missing or not 64 hex characters.
    ///
    /// The error names the variable that failed, never its value.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ShatterError> {
        let get = |name: &str| -> Result<[u8; 32], ShatterError> {
            let value = lookup(name).ok_or(ShatterError::InvalidParameter)?;
            parse_key(&value)
        };
        let vaults = match (
            lookup(KEY_VARS[0]),
            lookup(KEY_VARS[1]),
            lookup(KEY_VARS[2]),
        ) {
            (None, None, None) => None,
            (Some(a), Some(b), Some(c)) => Some(VaultKeys {
                a: parse_key(&a)?,
                b: parse_key(&b)?,
                c: parse_key(&c)?,
            }),
            _ => return Err(ShatterError::InvalidParameter),
        };
        Ok(Self {
            vaults,
            derivation: get(KEY_VARS[3])?,
            token: get(KEY_VARS[4])?,
            canary_master: get(KEY_VARS[5])?,
            audit: get(KEY_VARS[6])?,
            analytics: get(KEY_VARS[7])?,
        })
    }
}

/// Parses 64 hex characters into a 32-byte key.
pub fn parse_key(hex: &str) -> Result<[u8; 32], ShatterError> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(ShatterError::InvalidParameter);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| ShatterError::InvalidParameter)?;
    }
    Ok(out)
}

/// The record source the gateway reads through: the assembler, over the node's router.
pub struct Source {
    schema: Arc<ShatterSchema>,
    router: Arc<Router>,
    derivation: [u8; 32],
    metrics: Arc<Metrics>,
}

/// How long one read may wait on the vaults. It is shorter than the HTTP request timeout, so a
/// stalled vault gives a `503` from the assembler, and the blocking thread is freed at this
/// point rather than when the vault finally answers.
pub const READ_DEADLINE: Duration = Duration::from_secs(3);

impl RecordSource for Source {
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        let started = std::time::Instant::now();
        let record = assemble_with_deadline(
            &self.schema,
            &self.router,
            &self.derivation,
            shard,
            READ_DEADLINE,
        );
        self.metrics.observe_assembly(started.elapsed());
        record
    }
}

/// A node built from a configuration and keys, with its components wired together.
pub struct Node {
    config: Config,
    schema: Arc<ShatterSchema>,
    router: Arc<Router>,
    watch: Arc<CanaryWatch>,
    rotation: CanaryRotation,
    derivation: [u8; 32],
    signer: Arc<RwLock<Signer>>,
    gateway: Arc<Gateway<Source>>,
    orphans: Arc<OrphanStore>,
    issuer: Option<Arc<Issuer>>,
    /// The audit chain, shared by the issuer, the gateway, and the alarm response.
    audit: Arc<AuditStore>,
    /// The gateway's and writer's audit hook over `audit`.
    access_audit: Arc<dyn AccessAudit>,
    /// The analytics feed, when the config enables it.
    analytics: Option<Arc<Analytics>>,
    /// The same vault instances the router uses, kept for the purge pass.
    vaults: Vec<Arc<FileVault>>,
    retention: RetentionPolicy,
    metrics: Arc<Metrics>,
    /// Clients for the gateways' alarm listeners. Empty when none are configured.
    alarm_peers: Vec<AlarmPeer>,
    /// The client for the assembler's canary list listener. `None` when no push is configured.
    canary_peer: Option<CanaryPeer>,
}

/// Stores a shredded record through the node's shredder and its shared orphan store, and
/// feeds its anonymized form to analytics once the record is stored.
pub struct IngestSink {
    schema: Arc<ShatterSchema>,
    router: Arc<Router>,
    derivation: [u8; 32],
    orphans: Arc<OrphanStore>,
    analytics: Option<Arc<Analytics>>,
}

impl RecordSink for IngestSink {
    fn store(&self, shard: &ShardKey, record: Record) -> Result<(), ShatterError> {
        // Anonymize before the shredder consumes the record. A failure refuses the write.
        let prepared = match &self.analytics {
            Some(analytics) => Some(analytics.prepare(&record)?),
            None => None,
        };
        Shredder::with_store(
            &self.schema,
            &self.router,
            self.derivation,
            Arc::clone(&self.orphans),
        )
        .shred(shard, record)?;
        if let (Some(analytics), Some(events)) = (&self.analytics, prepared) {
            analytics.hold(events, now_secs())?;
        }
        Ok(())
    }
}

impl Node {
    /// Builds the node: opens the vaults, starts the watch, and prepares the gateway.
    ///
    /// Does not write canaries. Call [`Node::refresh_canaries`] for that.
    pub fn build(config: Config, keys: Keys) -> Result<Self, ShatterError> {
        validate(&config)?;
        let schema = Arc::new(ShatterSchema::load_json_file(&config.schema)?);
        fs::create_dir_all(&config.state_dir).map_err(|_| ShatterError::Internal)?;

        let retention = RetentionPolicy::new(config.retention_secs)?;
        let mut guards = Vec::with_capacity(3);
        // Local vaults are purged here. Remote vaults purge themselves (see `tpt-shatter-vault`).
        let mut vaults = Vec::with_capacity(3);
        if let Some(remote) = &config.remote_vaults {
            let tls = client_tls_from_files(&remote.ca, &remote.client_cert, &remote.client_key)?;
            let names = match &remote.server_names {
                Some(n) => [n.a.clone(), n.b.clone(), n.c.clone()],
                None => std::array::from_fn(|_| remote.server_name.clone()),
            };
            for ((vault, addr), name) in [
                (VaultId::A, &remote.a),
                (VaultId::B, &remote.b),
                (VaultId::C, &remote.c),
            ]
            .into_iter()
            .zip(names)
            {
                let backend = RemoteVault::new(vault, addr, &name, Arc::clone(&tls))?;
                guards.push(Guarded::new(
                    Box::new(backend),
                    BreakerConfig::default(),
                    system_clock(),
                ));
            }
        } else {
            let dirs = config
                .vault_dirs
                .as_ref()
                .ok_or(ShatterError::InvalidParameter)?;
            let local = keys.vaults.as_ref().ok_or(ShatterError::InvalidParameter)?;
            let backends: [(VaultId, &PathBuf, &[u8; 32]); 3] = [
                (VaultId::A, &dirs.a, &local.a),
                (VaultId::B, &dirs.b, &local.b),
                (VaultId::C, &dirs.c, &local.c),
            ];
            for (vault, dir, key) in backends {
                let file_vault = Arc::new(FileVault::open(vault, dir, key)?);
                let backend: Box<dyn VaultBackend> = Box::new(Arc::clone(&file_vault));
                vaults.push(file_vault);
                guards.push(Guarded::new(
                    backend,
                    BreakerConfig::default(),
                    system_clock(),
                ));
            }
        }

        let rotation = CanaryRotation::new(
            keys.canary_master,
            keys.derivation,
            config.canary_count,
            config.canary_period_secs,
        )?;
        let now = now_secs();
        let watch = Arc::new(CanaryWatch::new(&rotation.plan_at(now)?)?);
        let observer: Arc<dyn AccessObserver> = Arc::clone(&watch) as Arc<dyn AccessObserver>;
        let router = Arc::new(Router::new(guards)?.with_observer(observer));

        let signer = Arc::new(RwLock::new(Signer::new(1, keys.token)));
        let audit = Arc::new(AuditStore::open(
            &config.state_dir.join(AUDIT_LOG),
            keys.audit,
        )?);
        let access_audit: Arc<dyn AccessAudit> = Arc::new(NodeAudit::new(Arc::clone(&audit)));
        let metrics = Arc::new(Metrics::default());
        let source = Source {
            schema: Arc::clone(&schema),
            router: Arc::clone(&router),
            derivation: keys.derivation,
            metrics: Arc::clone(&metrics),
        };
        let limiter = RateLimiter::new(10, 2, 10_000)?;
        let gateway = Arc::new(
            Gateway::new(Arc::clone(&signer), source, limiter)
                .with_audit(Arc::clone(&access_audit)),
        );

        let analytics = match &config.analytics {
            Some(analytics_config) => {
                let policy = load_policy(&analytics_config.policy, &keys.analytics)?;
                let plan = export_plan(analytics_config)?;
                Some(Arc::new(Analytics::open(
                    policy,
                    &config.state_dir.join(ANALYTICS_LOG),
                    config.retention_secs,
                    plan,
                )?))
            }
            None => None,
        };

        let orphans = Arc::new(OrphanStore::open(&config.state_dir.join(ORPHAN_LOG))?);
        let issuer = match config.issuer.clone() {
            Some(issuer_config) => Some(Arc::new(Issuer::new(
                Arc::clone(&signer),
                &issuer_config,
                Arc::clone(&audit),
            )?)),
            None => None,
        };

        let alarm_peers = match &config.gateway_alarm {
            Some(alarm) => {
                let read = |path: &PathBuf| {
                    std::fs::read(path).map_err(|_| ShatterError::InvalidParameter)
                };
                let ca = read(&alarm.ca)?;
                let cert = read(&alarm.client_cert)?;
                let key = read(&alarm.client_key)?;
                let tls = client_config(&ca, Some((&cert, &key)))?;
                let timeout = Duration::from_secs(alarm.timeout_secs);
                alarm
                    .peers
                    .iter()
                    .map(|peer| {
                        AlarmPeer::new(&peer.addr, &peer.server_name, Arc::clone(&tls), timeout)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            None => Vec::new(),
        };

        let canary_peer = match &config.canary_push {
            Some(push) => {
                let read = |path: &PathBuf| {
                    std::fs::read(path).map_err(|_| ShatterError::InvalidParameter)
                };
                let tls = client_config(
                    &read(&push.ca)?,
                    Some((&read(&push.client_cert)?, &read(&push.client_key)?)),
                )?;
                Some(CanaryPeer::new(
                    &push.addr,
                    &push.server_name,
                    tls,
                    Duration::from_secs(push.timeout_secs),
                )?)
            }
            None => None,
        };

        Ok(Self {
            config,
            schema,
            router,
            watch,
            rotation,
            derivation: keys.derivation,
            signer,
            gateway,
            orphans,
            issuer,
            audit,
            access_audit,
            analytics,
            vaults,
            retention,
            metrics,
            alarm_peers,
            canary_peer,
        })
    }

    /// The configuration this node was built from.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// The gateway, for direct reads (used by tests and by the HTTP layer).
    #[must_use]
    pub fn gateway(&self) -> &Gateway<Source> {
        &self.gateway
    }

    /// The token issuer, when the config enables one.
    #[must_use]
    pub fn issuer(&self) -> Option<Arc<Issuer>> {
        self.issuer.clone()
    }

    /// The token signer. The issuer and the alarm response use it.
    #[must_use]
    pub fn signer(&self) -> Arc<RwLock<Signer>> {
        Arc::clone(&self.signer)
    }

    /// The router, for the vault client's own use.
    #[must_use]
    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    /// A shredder over the node's orphan store, which is backed by the state directory.
    /// Every shredder from this node shares one queue, so reaping and ingestion agree.
    #[must_use]
    pub fn shredder(&self) -> Shredder<'_> {
        Shredder::with_store(
            &self.schema,
            &self.router,
            self.derivation,
            Arc::clone(&self.orphans),
        )
    }

    /// The write path: stores records under shards, authorized by `Write`-scoped tokens.
    pub fn writer(&self) -> Result<Writer<IngestSink>, ShatterError> {
        let sink = IngestSink {
            schema: Arc::clone(&self.schema),
            router: Arc::clone(&self.router),
            derivation: self.derivation,
            orphans: Arc::clone(&self.orphans),
            analytics: self.analytics.clone(),
        };
        Ok(Writer::new(
            Arc::clone(&self.signer),
            sink,
            RateLimiter::new(10, 2, 10_000)?,
        )
        .with_audit(Arc::clone(&self.access_audit)))
    }

    /// Writes the canaries for the epoch containing `now` if they are not there yet, and
    /// erases the previous epoch's. Returns `true` when a refresh happened.
    ///
    /// The canary FragmentIds of the current epoch are written to the state directory on
    /// every call, after any refresh. A split assembler watches that list, so it must follow
    /// each epoch change.
    pub fn refresh_canaries(&self, now: u64) -> Result<bool, ShatterError> {
        let last = self.load_epoch()?;
        let refreshed = refresh_canaries(
            &self.rotation,
            &self.schema,
            &self.router,
            &self.derivation,
            last,
            now,
        )?;
        let changed = match refreshed {
            Some(epoch) => {
                self.store_epoch(epoch)?;
                self.watch.replace(&self.rotation.plan_at(now)?)?;
                true
            }
            None => false,
        };
        let ids = CanaryIds::from_plan(&self.rotation.plan_at(now)?, self.rotation.epoch(now)?)?;
        ids.write_file(&self.config.state_dir.join(CANARY_IDS))?;
        Ok(changed)
    }

    /// Pushes the canary list in the state directory to the assembler, when a push is
    /// configured. The monitor loop calls it after each refresh, so a failed push is retried on
    /// the next pass. The assembler refuses a list older than the one it holds.
    pub fn push_canary_ids(&self) -> Result<(), ShatterError> {
        let Some(peer) = &self.canary_peer else {
            return Ok(());
        };
        let text = fs::read_to_string(self.config.state_dir.join(CANARY_IDS))
            .map_err(|_| ShatterError::Internal)?;
        peer.push(&text)
    }

    /// Erases every fragment for `shard` (GDPR erasure). The request is recorded in the audit
    /// chain before any deletion, and the call fails if the record cannot be written, so no
    /// erasure happens unrecorded. Repeating the call is safe (see `erase`).
    pub fn erase_subject(&self, shard: &ShardKey, now: u64) -> Result<EraseReport, ShatterError> {
        access_audit::record_erasure(&self.audit, shard, now)?;
        erase(&self.router, &self.derivation, shard)
    }

    /// Erases the fragments in all three vaults whose retention has run out at `now`.
    /// Returns the totals across the vaults.
    pub fn purge_expired(&self, now: u64) -> Result<PurgeReport, ShatterError> {
        let mut total = PurgeReport::default();
        for vault in &self.vaults {
            let report = vault.purge_expired(self.retention, now)?;
            total.purged += report.purged;
            total.malformed += report.malformed;
        }
        self.metrics.record_purged(total.purged);
        Ok(total)
    }

    /// Emits held analytics events whose k-anonymity gate passes at `now`. Returns how many
    /// were emitted. Zero when analytics is off or the gate is not yet met.
    pub fn flush_analytics(&self, now: u64) -> Result<usize, ShatterError> {
        match &self.analytics {
            Some(analytics) => {
                let emitted = analytics.flush(now)?;
                self.metrics.record_analytics_emitted(emitted);
                Ok(emitted)
            }
            None => Ok(0),
        }
    }

    /// Produces the Prometheus text for `/metrics`. Vault gauges are read at each call.
    #[must_use]
    pub fn metrics_renderer(&self) -> Arc<dyn Fn() -> String + Send + Sync> {
        let metrics = Arc::clone(&self.metrics);
        let router = Arc::clone(&self.router);
        Arc::new(move || {
            let vaults = router.statuses().unwrap_or_default();
            metrics.render(&vaults)
        })
    }

    /// Writes the scheduled analytics exports at `now`. Returns how many files were written.
    /// Zero when analytics or the export schedule is off.
    pub fn write_analytics_exports(&self, now: u64) -> Result<usize, ShatterError> {
        match &self.analytics {
            Some(analytics) => analytics.write_exports(now),
            None => Ok(0),
        }
    }

    /// Erases analytics events past the retention window at `now`. Returns how many.
    pub fn purge_analytics(&self, now: u64) -> Result<usize, ShatterError> {
        match &self.analytics {
            Some(analytics) => analytics.purge(now),
            None => Ok(0),
        }
    }

    /// A monitor that drains the canary watch into the alarm gate and the alert log.
    pub fn monitor(&self) -> Result<CanaryMonitor, ShatterError> {
        Ok(CanaryMonitor::new(
            Arc::clone(&self.watch),
            self.config.alarm_cooldown_secs,
            self.alert_log()?,
        ))
    }

    /// Opens the security alert log in the state directory, for appending.
    pub fn alert_log(&self) -> Result<AlertLog, ShatterError> {
        AlertLog::open(&self.config.state_dir.join(ALERT_LOG))
    }

    /// The alarm response: rotate the token key, then notify. The notification writes the
    /// alarm to the audit chain. The monitor also writes every alarm to the alert log.
    pub fn responder(&self) -> AlarmResponder {
        // The rotator chooses the version and pushes the key to every gateway peer before
        // switching this node. A failed push leaves the old key in force.
        let rotator = SigningKeyRotator::with_peers(
            Arc::clone(&self.signer),
            Box::new(|| Ok::<[u8; 32], ShatterError>(random_key())),
            self.alarm_peers.clone(),
        );
        let audit = Arc::clone(&self.audit);
        let metrics = Arc::clone(&self.metrics);
        let notify = Box::new(move |alarm: &Alarm| {
            metrics.record_alarm();
            access_audit::record_alarm(&audit, alarm, now_secs())
        });
        AlarmResponder::new(rotator, notify)
    }

    /// Shared state for the HTTP layer. `access_log` receives one line per request.
    pub fn shared(
        &self,
        access_log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Shared<Source>, ShatterError> {
        // Every access line also feeds the request counters.
        let metrics = Arc::clone(&self.metrics);
        let access_log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |line: &str| {
            metrics.record_access_line(line);
            access_log(line);
        });
        let router = Arc::clone(&self.router);
        let breakers = Arc::new(move || {
            router
                .statuses()
                .map(|statuses| {
                    statuses
                        .iter()
                        .map(|s| s.state == BreakerState::Open)
                        .collect()
                })
                .unwrap_or_else(|_| vec![true; VaultId::ALL.len()])
        });
        let writer = Arc::new(self.writer()?);
        let write: WriteHandler = Arc::new(
            move |token: &str, shard_hex: &str, fields: &[(String, String)], now_ms: u64| {
                writer.write(token, shard_hex, fields, now_ms)
            },
        );
        Ok(Shared {
            gateway: Arc::clone(&self.gateway),
            breakers,
            access_log,
            config: HttpConfig::default(),
            source_limiter: Some(Mutex::new(RateLimiter::new(20, 5, 10_000)?)),
            writer: Some(write),
        })
    }

    fn load_epoch(&self) -> Result<Option<u64>, ShatterError> {
        match fs::read_to_string(self.config.state_dir.join(CANARY_EPOCH)) {
            Ok(text) => text
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| ShatterError::Internal),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ShatterError::Internal),
        }
    }

    fn store_epoch(&self, epoch: u64) -> Result<(), ShatterError> {
        fs::write(self.config.state_dir.join(CANARY_EPOCH), epoch.to_string())
            .map_err(|_| ShatterError::Internal)
    }
}

/// The export schedule from the config. `None` when no exports are configured.
fn export_plan(config: &AnalyticsConfig) -> Result<Option<ExportPlan>, ShatterError> {
    if config.exports.is_empty() {
        return Ok(None);
    }
    if config.export_interval_secs == 0 {
        return Err(ShatterError::InvalidParameter);
    }
    let dir = config
        .export_dir
        .clone()
        .ok_or(ShatterError::InvalidParameter)?;
    Ok(Some(ExportPlan {
        dir,
        exports: config.exports.clone(),
    }))
}

/// The analytics CSV for `group`: a count per group, or the sum of `value` when given.
/// Only events inside the retention window count, and groups with fewer than the policy's
/// `k` events are left out. Reads the analytics log without writing it.
pub fn export_analytics(
    config: &Config,
    keys: &Keys,
    group: &str,
    value: Option<&str>,
) -> Result<String, ShatterError> {
    let analytics_config = config
        .analytics
        .as_ref()
        .ok_or(ShatterError::InvalidParameter)?;
    let policy = load_policy(&analytics_config.policy, &keys.analytics)?;
    let cutoff = now_secs().saturating_sub(config.retention_secs);
    analytics::export_csv(
        &config.state_dir.join(ANALYTICS_LOG),
        policy.k(),
        cutoff,
        group,
        value,
    )
}

/// The compliance summary of the audit chain, as one JSON object (see `AuditReport`).
/// The chain is verified first, so a tampered log gives an error and no report. A missing
/// log is an empty chain. Reads the audit log without writing it.
pub fn export_audit(config: &Config, keys: &Keys) -> Result<String, ShatterError> {
    let path = config.state_dir.join(AUDIT_LOG);
    let records = match fs::read_to_string(&path) {
        Ok(text) => text
            .lines()
            .filter(|line| !line.is_empty())
            .map(AuditRecord::decode_line)
            .collect::<Result<Vec<_>, _>>()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(ShatterError::Internal),
    };
    Ok(report(keys.audit, &records)?.to_json())
}

/// Checks the numeric settings that would otherwise fail deep in a background loop.
fn validate(config: &Config) -> Result<(), ShatterError> {
    if config.canary_count == 0
        || config.canary_period_secs == 0
        || config.reap_interval_secs == 0
        || config.reap_max_attempts == 0
        || config.monitor_interval_secs == 0
        || config.purge_interval_secs == 0
        || config.retention_secs < config.canary_period_secs
    {
        return Err(ShatterError::InvalidParameter);
    }
    Ok(())
}

/// Seconds since the Unix epoch.
#[must_use]
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// 32 bytes from the thread-local CSPRNG.
fn random_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&rand::random::<u64>().to_be_bytes());
    }
    out
}

/// Loads a configuration file. Errors do not include the file's contents.
pub fn load_config(path: &Path) -> Result<Config, ShatterError> {
    let text = fs::read_to_string(path).map_err(|_| ShatterError::InvalidParameter)?;
    serde_json::from_str(&text).map_err(|_| ShatterError::InvalidParameter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_shatter_common::{Scope, Scopes};

    fn temp_root(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("tpt-shatter-node-{name}-{nanos}"))
    }

    fn hex_key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn keys() -> Keys {
        Keys {
            vaults: Some(VaultKeys {
                a: [0x01; 32],
                b: [0x02; 32],
                c: [0x03; 32],
            }),
            derivation: [0x04; 32],
            token: [0x05; 32],
            canary_master: [0x06; 32],
            audit: [0x07; 32],
            analytics: [0x08; 32],
        }
    }

    /// Writes a schema file and returns a config that uses directories under `root`.
    fn config(root: &Path) -> Config {
        fs::create_dir_all(root).expect("root");
        let schema = root.join("schema.json");
        fs::write(
            &schema,
            r#"{"version":1,"fields":{"name":"A","birth_year":"B","card_number":"C"}}"#,
        )
        .expect("schema");
        Config {
            listen: "127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            allow_plain_http: true,
            schema,
            state_dir: root.join("state"),
            vault_dirs: Some(VaultDirs {
                a: root.join("vault-a"),
                b: root.join("vault-b"),
                c: root.join("vault-c"),
            }),
            remote_vaults: None,
            canary_count: 2,
            canary_period_secs: 7 * 24 * 3600,
            alarm_cooldown_secs: 3600,
            reap_interval_secs: 60,
            reap_max_attempts: 5,
            monitor_interval_secs: 10,
            retention_secs: 30 * 24 * 3600,
            purge_interval_secs: 3600,
            issuer: None,
            analytics: None,
            metrics_listen: None,
            gateway_alarm: None,
            canary_push: None,
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
        ShardKey::from_bytes([0x7A; 32])
    }

    fn read_token(node: &Node, now: u64) -> String {
        let token = node
            .signer()
            .read()
            .expect("lock")
            .issue(&shard(), Scopes::from_scopes(&[Scope::Read]), now)
            .expect("issue");
        token.as_str().to_owned()
    }

    #[test]
    fn keys_are_read_by_name_and_must_be_hex() {
        let all =
            |name: &str| -> Option<String> { KEY_VARS.contains(&name).then(|| hex_key(0x11)) };
        assert!(Keys::from_lookup(all).is_ok());

        let missing = |name: &str| (name != KEY_VARS[4]).then(|| hex_key(0x11));
        assert_eq!(
            Keys::from_lookup(missing).err(),
            Some(ShatterError::InvalidParameter)
        );

        let short = |name: &str| {
            Some(if name == KEY_VARS[0] {
                "abcd".to_owned()
            } else {
                hex_key(0x11)
            })
        };
        assert_eq!(
            Keys::from_lookup(short).err(),
            Some(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn parse_key_round_trips_and_rejects_bad_digits() {
        assert_eq!(parse_key(&hex_key(0xAB)), Ok([0xAB; 32]));
        let bad = format!("zz{}", "00".repeat(31));
        assert_eq!(parse_key(&bad), Err(ShatterError::InvalidParameter));
    }

    #[test]
    fn a_record_shredded_by_the_node_is_read_back_through_the_gateway() {
        let root = temp_root("roundtrip");
        let node = Node::build(config(&root), keys()).expect("build");
        node.shredder().shred(&shard(), record()).expect("shred");

        let token = read_token(&node, now_secs());
        let response = node
            .gateway()
            .read(&token, &"7a".repeat(32), now_secs() * 1000);
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(response.status, 200, "{response:?}");
        assert!(
            response
                .fields
                .contains(&("name".to_owned(), "A. Example".to_owned()))
        );
    }

    fn token_with(node: &Node, scope: Scope, now: u64) -> String {
        node.signer()
            .read()
            .expect("lock")
            .issue(&shard(), Scopes::from_scopes(&[scope]), now)
            .expect("issue")
            .as_str()
            .to_owned()
    }

    #[test]
    fn a_write_through_the_node_is_read_back_and_scopes_are_enforced() {
        let root = temp_root("ingest");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        let writer = node.writer().expect("writer");
        let fields = vec![
            ("name".to_owned(), "A. Example".to_owned()),
            ("birth_year".to_owned(), "1990".to_owned()),
            ("card_number".to_owned(), "4111111111111111".to_owned()),
        ];
        let shard_hex = "7a".repeat(32);

        // A read token cannot write.
        let refused = writer.write(
            &token_with(&node, Scope::Read, now),
            &shard_hex,
            &fields,
            now * 1000,
        );
        assert_eq!(refused.status, 401);

        // A write token stores the record, and a read token reads it back.
        let stored = writer.write(
            &token_with(&node, Scope::Write, now),
            &shard_hex,
            &fields,
            now * 1000,
        );
        assert_eq!(stored.status, 201, "{stored:?}");
        let read =
            node.gateway()
                .read(&token_with(&node, Scope::Read, now), &shard_hex, now * 1000);
        assert_eq!(read.status, 200, "{read:?}");
        assert!(
            read.fields
                .contains(&("card_number".to_owned(), "4111111111111111".to_owned()))
        );

        // A field outside the schema is refused, and nothing is stored for it.
        let mut unknown = fields.clone();
        unknown.push(("shoe_size".to_owned(), "9".to_owned()));
        // The token is bound to this shard, so the refusal must come from the schema check.
        let bad = writer.write(
            &token_with(&node, Scope::Write, now),
            &shard_hex,
            &unknown,
            now * 1000,
        );
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(bad.status, 400, "{bad:?}");
    }

    #[test]
    fn a_canary_read_through_the_node_rotates_the_token_key() {
        let root = temp_root("alarm");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        assert_eq!(node.refresh_canaries(now), Ok(true));
        assert_eq!(
            node.refresh_canaries(now),
            Ok(false),
            "same epoch: nothing to do"
        );

        let token = read_token(&node, now);
        // Reading a canary through the router is the intrusion signal.
        let rotation =
            CanaryRotation::new(keys().canary_master, keys().derivation, 2, 7 * 24 * 3600)
                .expect("rotation");
        let plan = rotation.plan_at(now).expect("plan");
        let shard = plan.shard(0).expect("shard");
        let id =
            tpt_shatter_vault_client::derive_fragment_id(&keys().derivation, &shard, VaultId::A)
                .expect("id");
        let _ = node.router().get(VaultId::A, &id);

        let before = node.gateway().read(&token, &"7a".repeat(32), now * 1000);
        let mut monitor = node.monitor().expect("monitor");
        let outcome = monitor.poll(&node.responder(), now).expect("poll");
        let after = node.gateway().read(&token, &"7a".repeat(32), now * 1000);
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(after.status, 401, "the alarm must invalidate the old token");

        assert_eq!(outcome, tpt_shatter_canary::Outcome::Fired { alarms: 1 });
        // Before the alarm the token is valid, and the shard has no record, so 404.
        assert_eq!(before.status, 404, "{before:?}");
    }

    #[test]
    fn the_node_writes_the_current_canary_list_for_the_assembler() {
        let root = temp_root("canary-list");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.refresh_canaries(now).expect("refresh");

        let path = node.config().state_dir.join(CANARY_IDS);
        let listed = CanaryIds::read_file(&path);
        fs::remove_dir_all(&root).expect("cleanup");
        let listed = listed.expect("list");

        let rotation =
            CanaryRotation::new(keys().canary_master, keys().derivation, 2, 7 * 24 * 3600)
                .expect("rotation");
        assert_eq!(listed.epoch(), rotation.epoch(now).expect("epoch"));
        assert_eq!(listed.entries().len(), 2 * VaultId::ALL.len());
    }

    /// Collects what a subscriber writes, so a test can inspect the log output.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl CapturedLog {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLog;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn logs_and_alerts_never_contain_values_tokens_or_shard_keys() {
        let root = temp_root("logscan");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        let fields = vec![
            ("name".to_owned(), "A. Example".to_owned()),
            ("birth_year".to_owned(), "1990".to_owned()),
            ("card_number".to_owned(), "4111111111111111".to_owned()),
        ];
        let shard_hex = "7a".repeat(32);
        let write_token = token_with(&node, Scope::Write, now);
        let read_token = read_token(&node, now);

        // Every line the HTTP layer would log: successes and refusals, reads and writes.
        let writer = node.writer().expect("writer");
        let mut lines = vec![
            writer
                .write(&read_token, &shard_hex, &fields, now * 1000)
                .access_log_line(),
            writer
                .write(&write_token, &shard_hex, &fields, now * 1000)
                .access_log_line(),
            node.gateway()
                .read(&read_token, &shard_hex, now * 1000)
                .access_log_line(),
            node.gateway()
                .read("not-a-token", &shard_hex, now * 1000)
                .access_log_line(),
        ];

        // A canary read raises an alarm, which is written to the security alert log.
        assert_eq!(node.refresh_canaries(now), Ok(true));
        let rotation =
            CanaryRotation::new(keys().canary_master, keys().derivation, 2, 7 * 24 * 3600)
                .expect("rotation");
        let shard = rotation
            .plan_at(now)
            .expect("plan")
            .shard(0)
            .expect("shard");
        let id =
            tpt_shatter_vault_client::derive_fragment_id(&keys().derivation, &shard, VaultId::A)
                .expect("id");
        let _ = node.router().get(VaultId::A, &id);
        let mut monitor = node.monitor().expect("monitor");
        let outcome = monitor.poll(&node.responder(), now).expect("poll");
        assert_eq!(outcome, tpt_shatter_canary::Outcome::Fired { alarms: 1 });
        let alerts = fs::read_to_string(root.join("state").join(ALERT_LOG)).expect("alert log");
        lines.push(alerts);

        let secrets = [
            "A. Example",
            "1990",
            "4111111111111111",
            shard_hex.as_str(),
            read_token.as_str(),
            write_token.as_str(),
        ];
        // The same lines, through the JSON subscriber the binary installs. Whatever the
        // subscriber writes is what an operator's log shipper receives.
        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .finish();
        let sink = access_log_sink();
        tracing::subscriber::with_default(subscriber, || {
            for line in &lines {
                sink(line);
            }
        });
        let json = captured.text();
        assert!(json.contains("\"access\""), "no events captured: {json}");
        for secret in secrets {
            assert!(!json.contains(secret), "json log leaked {secret:?}: {json}");
        }

        fs::remove_dir_all(&root).expect("cleanup");
        for line in &lines {
            assert!(!line.is_empty(), "expected a log line");
            for secret in secrets {
                assert!(!line.contains(secret), "log leaked {secret:?}: {line}");
            }
        }
    }

    #[test]
    fn writes_reads_and_alarms_are_audited_without_raw_values() {
        use tpt_shatter_canary::{Alarm, Responder};
        use tpt_shatter_common::{AuditAction, AuditRecord, VaultId, verify_chain};

        let root = temp_root("audited");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();

        let write = node.writer().expect("writer").write(
            &token_with(&node, Scope::Write, now),
            &"7a".repeat(32),
            &[("name".to_owned(), "A. Example".to_owned())],
            now * 1000,
        );
        assert_eq!(write.status, 201, "{write:?}");
        let read = node
            .gateway()
            .read(&read_token(&node, now), &"7a".repeat(32), now * 1000);
        assert_eq!(read.status, 200, "{read:?}");
        node.responder()
            .notify_security(&Alarm {
                vault: VaultId::C,
                index: 0,
            })
            .expect("notify");

        let text = fs::read_to_string(root.join("state").join(AUDIT_LOG)).expect("log");
        let records: Vec<AuditRecord> = text
            .lines()
            .map(|line| AuditRecord::decode_line(line).expect("decode"))
            .collect();
        assert_eq!(verify_chain(keys().audit, &records), Ok(()));
        let actions: Vec<AuditAction> = records.iter().map(|r| r.event().action).collect();
        assert_eq!(
            actions,
            [AuditAction::Ingest, AuditAction::Read, AuditAction::Alarm]
        );
        assert_eq!(records[2].event().vault, Some(VaultId::C));
        assert!(!text.contains(&"7a".repeat(32)), "shard key in the log");
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// A write token for the shard whose bytes are all `byte`.
    fn write_token_for(node: &Node, byte: u8, now: u64) -> String {
        node.signer()
            .read()
            .expect("lock")
            .issue(
                &ShardKey::from_bytes([byte; 32]),
                Scopes::from_scopes(&[Scope::Write]),
                now,
            )
            .expect("issue")
            .as_str()
            .to_owned()
    }

    /// Writes one person to the shard `byte`. Returns the HTTP-style status.
    fn write_person(node: &Node, byte: u8, year: &str, now: u64) -> u16 {
        let fields = [
            ("name".to_owned(), "A. Example".to_owned()),
            ("birth_year".to_owned(), year.to_owned()),
            ("card_number".to_owned(), "4111111111111111".to_owned()),
        ];
        node.writer()
            .expect("writer")
            .write(
                &write_token_for(node, byte, now),
                &format!("{byte:02x}").repeat(32),
                &fields,
                now * 1000,
            )
            .status
    }

    /// Writes a policy file with the given `k`, bucketing years and masking cards.
    fn write_policy(root: &Path, k: usize) -> PathBuf {
        let path = root.join("policy.json");
        let policy = serde_json::json!({
            "k": k,
            "quasi_identifiers": ["birth_year"],
            "rules": {
                "name": "pseudonymize",
                "birth_year": {"bucket": {"width": 10}},
                "card_number": {"mask": {"keep_last": 4}}
            }
        });
        fs::write(&path, policy.to_string()).expect("policy");
        path
    }

    #[test]
    fn analytics_holds_each_write_until_the_gate_passes_then_emits_anonymized_events() {
        let root = temp_root("analytics");
        let mut cfg = config(&root);
        cfg.analytics = Some(AnalyticsConfig {
            policy: write_policy(&root, 2),
            export_dir: None,
            exports: Vec::new(),
            export_interval_secs: 3600,
        });
        let node = Node::build(cfg, keys()).expect("build");
        let now = now_secs();
        let log = root.join("state").join(ANALYTICS_LOG);

        assert_eq!(write_person(&node, 0x31, "1994", now), 201);
        assert_eq!(
            node.flush_analytics(now).expect("flush"),
            0,
            "one event is below k=2"
        );
        assert_eq!(fs::read_to_string(&log).expect("log"), "");

        assert_eq!(write_person(&node, 0x32, "1996", now), 201);
        assert_eq!(node.flush_analytics(now).expect("flush"), 2);
        let text = fs::read_to_string(&log).expect("log");
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("1990-1999"), "bucket missing: {text}");
        assert!(!text.contains("A. Example"), "name leaked: {text}");
        assert!(!text.contains("4111111111"), "card leaked: {text}");
    }

    #[test]
    fn scheduled_exports_are_written_to_the_export_directory() {
        let root = temp_root("exports");
        let export_dir = root.join("exports");
        fs::create_dir_all(&export_dir).expect("export dir");
        let mut cfg = config(&root);
        cfg.analytics = Some(AnalyticsConfig {
            policy: write_policy(&root, 2),
            export_dir: Some(export_dir.clone()),
            exports: vec![ExportConfig {
                group: "birth_year".to_owned(),
                value: None,
                file: "by_decade.csv".to_owned(),
            }],
            export_interval_secs: 60,
        });
        let node = Node::build(cfg, keys()).expect("build");
        let now = now_secs();
        assert_eq!(write_person(&node, 0x41, "1994", now), 201);
        assert_eq!(write_person(&node, 0x42, "1996", now), 201);
        assert_eq!(node.flush_analytics(now).expect("flush"), 2);

        assert_eq!(node.write_analytics_exports(now).expect("export"), 1);
        let csv = fs::read_to_string(export_dir.join("by_decade.csv")).expect("csv");
        assert!(
            !export_dir.join("by_decade.csv.tmp").exists(),
            "temp file left behind"
        );
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(csv, "birth_year,count\n1990-1999,2\n");
    }

    #[test]
    fn the_audit_export_counts_verified_events_and_holds_no_digests() {
        let root = temp_root("audit-export");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        let empty: serde_json::Value =
            serde_json::from_str(&export_audit(&config(&root), &keys()).expect("empty"))
                .expect("json");
        assert_eq!(empty["records"], 0);

        let write = node.writer().expect("writer").write(
            &token_with(&node, Scope::Write, now),
            &"7a".repeat(32),
            &[("name".to_owned(), "A. Example".to_owned())],
            now * 1000,
        );
        assert_eq!(write.status, 201, "{write:?}");
        let read = node
            .gateway()
            .read(&read_token(&node, now), &"7a".repeat(32), now * 1000);
        assert_eq!(read.status, 200, "{read:?}");

        let text = export_audit(&config(&root), &keys()).expect("export");
        let json: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(json["records"], 2);
        assert_eq!(json["by_action"]["ingest"], 1);
        assert_eq!(json["by_action"]["read"], 1);
        assert!(json["head_mac"].is_string());
        assert!(!text.contains(&"7a".repeat(32)), "shard key in the export");
        assert!(!text.contains("A. Example"), "record value in the export");

        let mut wrong = keys();
        wrong.audit = [0x09; 32];
        assert!(
            export_audit(&config(&root), &wrong).is_err(),
            "wrong key verified"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn erasure_is_recorded_before_it_deletes_and_leaves_nothing_readable() {
        use tpt_shatter_common::{AuditAction, AuditRecord};

        let root = temp_root("erase");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");

        let report = node.erase_subject(&shard(), now).expect("erase");
        assert_eq!(report.rows_removed, 3);
        assert!(report.verified);
        let read = node
            .gateway()
            .read(&read_token(&node, now), &"7a".repeat(32), now * 1000);
        assert_ne!(read.status, 200, "{read:?}");
        assert!(read.fields.is_empty());

        let repeat = node.erase_subject(&shard(), now).expect("repeat");
        assert_eq!(repeat.rows_removed, 0);
        assert!(repeat.verified);

        let text = fs::read_to_string(root.join("state").join(AUDIT_LOG)).expect("log");
        assert!(!text.contains(&"7a".repeat(32)), "shard key in the log");
        let erasures: Vec<AuditRecord> = text
            .lines()
            .map(|line| AuditRecord::decode_line(line).expect("decode"))
            .filter(|r| r.event().action == AuditAction::Erasure)
            .collect();
        assert_eq!(erasures.len(), 2, "one record per erasure request");
        assert!(erasures.iter().all(|r| r.event().vault.is_none()));
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Pen-style checks on the token rules, run through the node's gateway. HTTP adds only
    /// parsing on top of `Gateway::read`, so these exercise the same decisions.
    #[test]
    fn keys_load_from_a_directory_and_match_the_environment_source() {
        let root = temp_root("keys-dir");
        fs::create_dir_all(&root).expect("dir");
        for (i, name) in KEY_VARS.iter().enumerate() {
            fs::write(
                root.join(name),
                format!(
                    "{}
",
                    hex_key(i as u8 + 1)
                ),
            )
            .expect("write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o400))
                    .expect("mode");
            }
        }
        let from_dir = Keys::from_dir(&root).expect("load");
        let from_env = Keys::from_lookup(|name| {
            let i = KEY_VARS.iter().position(|v| *v == name)?;
            Some(hex_key(i as u8 + 1))
        })
        .expect("env");
        assert_eq!(
            from_dir.vaults.as_ref().map(|v| v.a),
            from_env.vaults.as_ref().map(|v| v.a)
        );
        assert_eq!(from_dir.audit, from_env.audit);
        assert_eq!(from_dir.analytics, from_env.analytics);

        fs::remove_file(root.join(KEY_VARS[4])).expect("remove");
        assert!(Keys::from_dir(&root).is_err(), "a missing key loaded");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(root.join(KEY_VARS[4]), hex_key(9)).expect("write");
            fs::set_permissions(root.join(KEY_VARS[4]), fs::Permissions::from_mode(0o640))
                .expect("mode");
            assert!(
                Keys::from_dir(&root).is_err(),
                "a group-readable key loaded"
            );
        }
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn a_replayed_token_works_within_its_ttl_and_not_after() {
        // Decision: replay resistance is the short TTL alone (DECISIONS.md).
        let root = temp_root("pen-replay");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");
        let token = read_token(&node, now);

        let first = node.gateway().read(&token, &"7a".repeat(32), now * 1000);
        let replay = node
            .gateway()
            .read(&token, &"7a".repeat(32), (now + 1) * 1000);
        let late = node.gateway().read(
            &token,
            &"7a".repeat(32),
            (now + 10 * tpt_shatter_common::DEFAULT_TOKEN_TTL_SECS) * 1000,
        );
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(first.status, 200, "{first:?}");
        assert_eq!(replay.status, 200, "{replay:?}");
        assert_ne!(late.status, 200, "{late:?}");
        assert!(late.fields.is_empty());
    }

    #[test]
    fn a_tampered_or_mis_scoped_token_reads_nothing() {
        let root = temp_root("pen-tamper");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");
        let token = read_token(&node, now);

        // Flip the last character of the signature.
        let mut tampered = token.clone();
        let last = tampered.pop().expect("token");
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let flipped = node.gateway().read(&tampered, &"7a".repeat(32), now * 1000);
        assert_ne!(flipped.status, 200, "{flipped:?}");
        assert!(flipped.fields.is_empty());

        // A token for shard 7a presented for shard 7b.
        let other = node.gateway().read(&token, &"7b".repeat(32), now * 1000);
        assert_ne!(other.status, 200, "{other:?}");
        assert!(other.fields.is_empty());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Measurement, not a gate. Prints latency percentiles for the assembler read path.
    /// Run with `cargo test -p tpt-shatter-node read_path_latency -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement only: run with --ignored --nocapture"]
    fn read_path_latency() {
        use std::time::Instant;
        use tpt_shatter_assembler::assemble_with_deadline;

        let root = temp_root("latency");
        let node = Node::build(config(&root), keys()).expect("build");
        node.shredder().shred(&shard(), record()).expect("shred");
        let router = node.router();

        const SAMPLES: usize = 500;
        let mut micros: Vec<u128> = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let started = Instant::now();
            let rebuilt = assemble_with_deadline(
                &node.schema,
                &router,
                &node.derivation,
                &shard(),
                READ_DEADLINE,
            )
            .expect("assemble");
            micros.push(started.elapsed().as_micros());
            assert_eq!(rebuilt.len(), 3);
        }
        micros.sort_unstable();
        let pct = |p: usize| micros[(SAMPLES * p / 100).min(SAMPLES - 1)];
        println!(
            "read path, {SAMPLES} reads, 3 vaults, in-process file vaults: p50 {} us, p95 {} us, p99 {} us",
            pct(50),
            pct(95),
            pct(99)
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn reads_are_attributed_to_the_caller_the_token_was_issued_to() {
        use tpt_shatter_common::{
            AuditAction, AuditRecord, CALLER_TAG_LEN, DEFAULT_TOKEN_TTL_SECS,
        };

        let root = temp_root("attribution");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");

        let tag = [0x5C; CALLER_TAG_LEN];
        let token = node
            .signer()
            .read()
            .expect("lock")
            .issue_for(
                &tag,
                &shard(),
                Scopes::from_scopes(&[Scope::Read]),
                now,
                DEFAULT_TOKEN_TTL_SECS,
            )
            .expect("issue");
        let read = node.gateway().read(&token, &"7a".repeat(32), now * 1000);
        assert_eq!(read.status, 200, "{read:?}");

        let text = fs::read_to_string(root.join("state").join(AUDIT_LOG)).expect("log");
        fs::remove_dir_all(&root).expect("cleanup");
        let reads: Vec<AuditRecord> = text
            .lines()
            .map(|line| AuditRecord::decode_line(line).expect("decode"))
            .filter(|r| r.event().action == AuditAction::Read)
            .collect();
        assert_eq!(reads.len(), 1);
        let expected =
            tpt_shatter_vault_client::keyed_digest(&keys().audit, b"tpt-shatter/caller", &tag)
                .expect("digest");
        assert_eq!(reads[0].event().caller, Some(expected));
        assert!(
            !text.contains(&"5c".repeat(CALLER_TAG_LEN)),
            "raw caller tag in the log"
        );
    }

    #[test]
    fn remote_vaults_take_a_name_per_vault_when_given_one() {
        let shared: RemoteVaults = serde_json::from_str(
            r#"{"a":"x:1","b":"y:1","c":"z:1","server_name":"vault.internal",
                "ca":"ca","client_cert":"c","client_key":"k"}"#,
        )
        .expect("shared name");
        assert!(shared.server_names.is_none());

        let per_vault: RemoteVaults = serde_json::from_str(
            r#"{"a":"x:1","b":"y:1","c":"z:1","server_name":"unused",
                "server_names":{"a":"a.internal","b":"b.internal","c":"c.internal"},
                "ca":"ca","client_cert":"c","client_key":"k"}"#,
        )
        .expect("per-vault names");
        let names = per_vault.server_names.expect("names");
        assert_eq!(
            (names.a, names.b, names.c),
            (
                "a.internal".to_owned(),
                "b.internal".to_owned(),
                "c.internal".to_owned()
            )
        );

        let partial = serde_json::from_str::<RemoteVaults>(
            r#"{"a":"x:1","b":"y:1","c":"z:1","server_name":"n",
                "server_names":{"a":"a.internal"},
                "ca":"ca","client_cert":"c","client_key":"k"}"#,
        );
        assert!(partial.is_err(), "a partial name map is refused");
    }

    #[test]
    fn gateway_alarm_peers_parse_and_refuse_unknown_fields() {
        let ok: GatewayAlarm = serde_json::from_str(
            r#"{"peers":[{"addr":"g1:7445","server_name":"gw"}],
                "ca":"ca","client_cert":"c","client_key":"k"}"#,
        )
        .expect("parses");
        assert_eq!(ok.peers.len(), 1);
        assert_eq!(ok.timeout_secs, 5);

        let typo = serde_json::from_str::<GatewayAlarm>(
            r#"{"peers":[],"ca":"ca","client_cert":"c","client_key":"k","timout_secs":3}"#,
        );
        assert!(typo.is_err(), "a misspelled field is refused");
    }

    #[test]
    fn a_record_round_trips_through_three_remote_vault_services() {
        use std::net::TcpListener;
        use tpt_shatter_vault_client::FileVault;
        use tpt_shatter_vault_service::{serve, server_tls};

        // TEST-ONLY certificates from the gateway's fixtures, for loopback TLS.
        let fixtures = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tpt-shatter-gateway/tests/fixtures/"
        );
        let fixture = |name: &str| PathBuf::from(format!("{fixtures}{name}"));
        let root = temp_root("remote");

        let mut addresses = Vec::new();
        for (vault, key_byte) in [(VaultId::A, 0x21u8), (VaultId::B, 0x22), (VaultId::C, 0x23)] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            addresses.push(listener.local_addr().expect("addr").to_string());
            let dir = root.join(format!("service-{}", vault.label()));
            let store = Arc::new(FileVault::open(vault, &dir, &[key_byte; 32]).expect("open"));
            let tls = server_tls(
                &fs::read(fixture("server.pem")).expect("cert"),
                &fs::read(fixture("server.key")).expect("key"),
                &fs::read(fixture("ca.pem")).expect("ca"),
            )
            .expect("tls");
            let backend: Arc<dyn VaultBackend> = store;
            std::thread::spawn(move || {
                let _ = serve(listener, tls, backend);
            });
        }

        let mut cfg = config(&root);
        cfg.vault_dirs = None;
        cfg.remote_vaults = Some(RemoteVaults {
            a: addresses[0].clone(),
            b: addresses[1].clone(),
            c: addresses[2].clone(),
            server_name: "localhost".to_owned(),
            server_names: None,
            ca: fixture("ca.pem"),
            client_cert: fixture("client.pem"),
            client_key: fixture("client.key"),
        });
        // The node holds no vault keys in this mode.
        let mut node_keys = keys();
        node_keys.vaults = None;
        let node = Node::build(cfg, node_keys).expect("build");

        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");
        let read = node
            .gateway()
            .read(&read_token(&node, now), &"7a".repeat(32), now * 1000);
        assert_eq!(read.status, 200, "{read:?}");
        assert!(
            read.fields
                .contains(&("name".to_owned(), "A. Example".to_owned()))
        );

        // Each service holds exactly its own fragment.
        for label in ['A', 'B', 'C'] {
            let files = fs::read_dir(root.join(format!("service-{label}")))
                .expect("service dir")
                .count();
            assert_eq!(files, 1, "vault {label}");
        }
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn a_fragment_copied_into_another_vault_reads_nothing() {
        // An attacker with file access copies vault B's fragment over vault A's file. Each
        // fragment is sealed with its vault label and FragmentId as associated data, so the
        // copy must fail to open rather than yield a field.
        let root = temp_root("pen-cross");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");
        let token = read_token(&node, now);
        let control = node.gateway().read(&token, &"7a".repeat(32), now * 1000);
        assert_eq!(control.status, 200, "{control:?}");

        let only_file = |dir: PathBuf| -> PathBuf {
            let files: Vec<PathBuf> = fs::read_dir(&dir)
                .expect("dir")
                .map(|entry| entry.expect("entry").path())
                .collect();
            assert_eq!(files.len(), 1, "one fragment per vault in {dir:?}");
            files[0].clone()
        };
        let from_b = only_file(root.join("vault-b"));
        let into_a = only_file(root.join("vault-a"));
        fs::copy(&from_b, &into_a).expect("copy");

        let read = node
            .gateway()
            .read(&read_token(&node, now), &"7a".repeat(32), now * 1000);
        fs::remove_dir_all(&root).expect("cleanup");
        assert_ne!(read.status, 200, "{read:?}");
        assert!(read.fields.is_empty());
    }

    #[test]
    fn an_export_name_that_is_not_a_plain_file_name_is_refused() {
        let root = temp_root("export-name");
        let mut cfg = config(&root);
        cfg.analytics = Some(AnalyticsConfig {
            policy: write_policy(&root, 2),
            export_dir: Some(root.clone()),
            exports: vec![ExportConfig {
                group: "birth_year".to_owned(),
                value: None,
                file: "../escape.csv".to_owned(),
            }],
            export_interval_secs: 60,
        });
        let result = Node::build(cfg, keys()).err();
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(result, Some(ShatterError::InvalidParameter));
    }

    #[test]
    fn analytics_events_expire_with_the_retention_window() {
        let root = temp_root("analytics-purge");
        let mut cfg = config(&root);
        let retention = cfg.retention_secs;
        cfg.analytics = Some(AnalyticsConfig {
            policy: write_policy(&root, 1),
            export_dir: None,
            exports: Vec::new(),
            export_interval_secs: 3600,
        });
        let node = Node::build(cfg, keys()).expect("build");
        let now = now_secs();

        assert_eq!(write_person(&node, 0x33, "1994", now), 201);
        assert_eq!(node.flush_analytics(now).expect("flush"), 1);
        // The event was stored a moment after `now`, so the offsets leave room for that.
        assert_eq!(
            node.purge_analytics(now + retention - 10).expect("purge"),
            0,
            "still inside the window"
        );
        assert_eq!(
            node.purge_analytics(now + retention + 10).expect("purge"),
            1
        );
        let text = fs::read_to_string(root.join("state").join(ANALYTICS_LOG)).expect("log");
        fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(text, "");
    }

    #[test]
    fn purge_keeps_live_fragments_and_erases_expired_ones() {
        let root = temp_root("purge");
        let node = Node::build(config(&root), keys()).expect("build");
        let now = now_secs();
        node.shredder().shred(&shard(), record()).expect("shred");
        node.refresh_canaries(now).expect("canaries");

        // Inside retention: nothing is purged, and the record still reads.
        assert_eq!(
            node.purge_expired(now),
            Ok(PurgeReport {
                purged: 0,
                malformed: 0
            })
        );
        let token = read_token(&node, now);
        let live = node.gateway().read(&token, &"7a".repeat(32), now * 1000);
        assert_eq!(live.status, 200, "{live:?}");

        // Past retention: the record and the canaries are erased, and a second pass finds nothing.
        let later = now + 30 * 24 * 3600 + 10;
        let report = node.purge_expired(later).expect("purge");
        assert_eq!(report.malformed, 0, "{report:?}");
        assert!(report.purged >= 3, "{report:?}");
        assert_eq!(
            node.purge_expired(later),
            Ok(PurgeReport {
                purged: 0,
                malformed: 0
            })
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn retention_shorter_than_the_canary_period_is_refused() {
        let root = temp_root("retention");
        let mut cfg = config(&root);
        cfg.retention_secs = cfg.canary_period_secs - 1;
        assert_eq!(
            Node::build(cfg, keys()).err(),
            Some(ShatterError::InvalidParameter)
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn invalid_settings_are_refused_before_anything_is_opened() {
        let root = temp_root("invalid");
        let mut cfg = config(&root);
        cfg.reap_interval_secs = 0;
        assert_eq!(
            Node::build(cfg, keys()).err(),
            Some(ShatterError::InvalidParameter)
        );
        fs::remove_dir_all(&root).ok();
    }
}
