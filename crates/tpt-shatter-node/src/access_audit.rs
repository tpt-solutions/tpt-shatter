// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Writes the node's reads, writes, and canary alarms to the audit chain.
//!
//! Token and shard digests are keyed with the audit key and a per-action domain, the same
//! way issuance digests are. Alarms have no token or shard, so their digests are all zero.

use std::sync::Arc;

use tpt_shatter_canary::Alarm;
use tpt_shatter_common::{
    AUDIT_DIGEST_LEN, AuditAction, AuditEvent, Scope, ShardKey, ShatterError,
};
use tpt_shatter_gateway::AccessAudit;
use tpt_shatter_vault_client::keyed_digest;

use crate::issuer::AuditStore;

/// Digest placeholder for events that concern no token or shard.
const NO_DIGEST: [u8; AUDIT_DIGEST_LEN] = [0; AUDIT_DIGEST_LEN];

/// Records authorized gateway operations on the node's audit chain.
pub struct NodeAudit {
    store: Arc<AuditStore>,
}

impl NodeAudit {
    /// Records to `store`, which the issuer shares.
    #[must_use]
    pub const fn new(store: Arc<AuditStore>) -> Self {
        Self { store }
    }
}

impl AccessAudit for NodeAudit {
    fn authorized(
        &self,
        scope: Scope,
        token: &str,
        shard: &ShardKey,
        now: u64,
    ) -> Result<(), ShatterError> {
        let (action, token_domain, shard_domain): (AuditAction, &[u8], &[u8]) = match scope {
            Scope::Read => (
                AuditAction::Read,
                b"tpt-shatter/read/token",
                b"tpt-shatter/read/shard",
            ),
            Scope::Write => (
                AuditAction::Ingest,
                b"tpt-shatter/ingest/token",
                b"tpt-shatter/ingest/shard",
            ),
            Scope::Delete => return Err(ShatterError::InvalidParameter),
        };
        self.store.record(AuditEvent {
            action,
            token_digest: keyed_digest(self.store.key(), token_domain, token.as_bytes())?,
            shard_digest: keyed_digest(self.store.key(), shard_domain, shard.as_bytes())?,
            vault: None,
            at: now,
        })
    }
}

/// Records one canary alarm. Only the vault is kept, as in the alert log.
pub fn record_alarm(store: &AuditStore, alarm: &Alarm, at: u64) -> Result<(), ShatterError> {
    store.record(AuditEvent {
        action: AuditAction::Alarm,
        token_digest: NO_DIGEST,
        shard_digest: NO_DIGEST,
        vault: Some(alarm.vault),
        at,
    })
}
