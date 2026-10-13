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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::Deserialize;
use tpt_shatter_assembler::Assembler;
use tpt_shatter_canary::{Alarm, CanaryMonitor, CanaryRotation, CanaryWatch, refresh_canaries};
use tpt_shatter_common::{
    AlertLog, Record, RetentionPolicy, ShardKey, ShatterError, ShatterSchema, VaultId,
};
use tpt_shatter_gateway::{
    AccessAudit, AlarmResponder, Gateway, HttpConfig, RateLimiter, RecordSink, RecordSource,
    Shared, SigningKeyRotator, WriteHandler, Writer,
};
use tpt_shatter_shredder::{OrphanStore, Shredder};

use access_audit::NodeAudit;
pub use issuer::{AuditStore, IssueOutcome, Issuer, IssuerConfig, serve_issuer};
mod access_audit;
mod analytics;
mod issuer;

use analytics::{Analytics, load_policy};
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

/// The analytics feed. Off unless the config names a policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsConfig {
    /// The anonymization policy (JSON). See `analytics.rs` for the format. Its events are kept
    /// for `retention_secs`, the same window as vault fragments.
    pub policy: PathBuf,
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
    /// The vault directories.
    pub vault_dirs: VaultDirs,
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
}

/// The eight 32-byte keys a node needs. Each is 64 hex characters in the environment.
///
/// Keys are read from the environment at boot and held in RAM. Key delivery from a
/// secret store is not built, so the environment is the interim source.
pub struct Keys {
    /// Sealing key for vault A.
    pub vault_a: [u8; 32],
    /// Sealing key for vault B.
    pub vault_b: [u8; 32],
    /// Sealing key for vault C.
    pub vault_c: [u8; 32],
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
    /// Reads every key with `lookup`. Fails if any is missing or not 64 hex characters.
    ///
    /// The error names the variable that failed, never its value.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ShatterError> {
        let get = |name: &str| -> Result<[u8; 32], ShatterError> {
            let value = lookup(name).ok_or(ShatterError::InvalidParameter)?;
            parse_key(&value)
        };
        Ok(Self {
            vault_a: get(KEY_VARS[0])?,
            vault_b: get(KEY_VARS[1])?,
            vault_c: get(KEY_VARS[2])?,
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
}

impl RecordSource for Source {
    fn fetch(&self, shard: &ShardKey) -> Result<Record, ShatterError> {
        Assembler::new(&self.schema, &self.router, self.derivation).assemble(shard)
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

        let backends: [(VaultId, &PathBuf, &[u8; 32]); 3] = [
            (VaultId::A, &config.vault_dirs.a, &keys.vault_a),
            (VaultId::B, &config.vault_dirs.b, &keys.vault_b),
            (VaultId::C, &config.vault_dirs.c, &keys.vault_c),
        ];
        let retention = RetentionPolicy::new(config.retention_secs)?;
        let mut guards = Vec::with_capacity(3);
        let mut vaults = Vec::with_capacity(3);
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
        let source = Source {
            schema: Arc::clone(&schema),
            router: Arc::clone(&router),
            derivation: keys.derivation,
        };
        let limiter = RateLimiter::new(10, 2, 10_000)?;
        let gateway = Arc::new(
            Gateway::new(Arc::clone(&signer), source, limiter)
                .with_audit(Arc::clone(&access_audit)),
        );

        let analytics = match &config.analytics {
            Some(analytics_config) => {
                let policy = load_policy(&analytics_config.policy, &keys.analytics)?;
                Some(Arc::new(Analytics::open(
                    policy,
                    &config.state_dir.join(ANALYTICS_LOG),
                    config.retention_secs,
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
        match refreshed {
            Some(epoch) => {
                self.store_epoch(epoch)?;
                self.watch.replace(&self.rotation.plan_at(now)?)?;
                Ok(true)
            }
            None => Ok(false),
        }
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
        Ok(total)
    }

    /// Emits held analytics events whose k-anonymity gate passes at `now`. Returns how many
    /// were emitted. Zero when analytics is off or the gate is not yet met.
    pub fn flush_analytics(&self, now: u64) -> Result<usize, ShatterError> {
        match &self.analytics {
            Some(analytics) => analytics.flush(now),
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
        let version = Arc::new(AtomicU32::new(1));
        let next_key = Box::new(move || {
            let v = version.fetch_add(1, Ordering::SeqCst) + 1;
            Ok((v, random_key()))
        });
        let rotator = SigningKeyRotator::new(Arc::clone(&self.signer), next_key);
        let audit = Arc::clone(&self.audit);
        let notify =
            Box::new(move |alarm: &Alarm| access_audit::record_alarm(&audit, alarm, now_secs()));
        AlarmResponder::new(rotator, notify)
    }

    /// Shared state for the HTTP layer. `access_log` receives one line per request.
    pub fn shared(
        &self,
        access_log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Shared<Source>, ShatterError> {
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
            vault_a: [0x01; 32],
            vault_b: [0x02; 32],
            vault_c: [0x03; 32],
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
            vault_dirs: VaultDirs {
                a: root.join("vault-a"),
                b: root.join("vault-b"),
                c: root.join("vault-c"),
            },
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
    fn analytics_events_expire_with_the_retention_window() {
        let root = temp_root("analytics-purge");
        let mut cfg = config(&root);
        let retention = cfg.retention_secs;
        cfg.analytics = Some(AnalyticsConfig {
            policy: write_policy(&root, 1),
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
