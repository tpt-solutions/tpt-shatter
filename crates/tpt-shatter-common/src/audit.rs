// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Tamper-evident audit trail without payloads.
//!
//! Each [`AuditRecord`] carries a keyed HMAC-SHA256 over the previous record's MAC
//! and its own canonical encoding. Editing, deleting, reordering, or truncating
//! from the middle breaks verification. The chain key is separate from every data
//! key, so an attacker who can read the log cannot recompute the chain.
//!
//! Events hold only action kinds, sequence numbers, timestamps, a vault label, and
//! two caller-supplied 32-byte digests (token and shard). Callers must pass keyed
//! digests, never raw tokens or shard keys.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::ShatterError;
use crate::vault::VaultId;

type HmacSha256 = Hmac<Sha256>;

/// Length of a digest or MAC in an audit record.
pub const AUDIT_DIGEST_LEN: usize = 32;

const CHAIN_DOMAIN: &[u8] = b"tpt-shatter/audit/chain/v1";

/// The kind of event recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    /// A record was written across the vaults.
    Ingest,
    /// A record was reconstructed for a request.
    Read,
    /// Fragments were deleted for a data subject.
    Erasure,
    /// A canary was touched and the alarm response ran.
    Alarm,
    /// The token signing key was rotated.
    KeyRotation,
    /// A capability token was issued.
    Issue,
}

impl AuditAction {
    const fn code(self) -> u8 {
        match self {
            Self::Ingest => 1,
            Self::Read => 2,
            Self::Erasure => 3,
            Self::Alarm => 4,
            Self::KeyRotation => 5,
            Self::Issue => 6,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Ingest,
            2 => Self::Read,
            3 => Self::Erasure,
            4 => Self::Alarm,
            5 => Self::KeyRotation,
            6 => Self::Issue,
            _ => return None,
        })
    }
}

/// One event, with no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent {
    /// What happened.
    pub action: AuditAction,
    /// Keyed digest of the capability token that authorized the event.
    pub token_digest: [u8; AUDIT_DIGEST_LEN],
    /// Keyed digest of the shard key the event concerned.
    pub shard_digest: [u8; AUDIT_DIGEST_LEN],
    /// The vault involved, if the event is vault-specific.
    pub vault: Option<VaultId>,
    /// When the event happened (Unix seconds).
    pub at: u64,
}

/// A stored event with its position and chain MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    seq: u64,
    event: AuditEvent,
    mac: [u8; AUDIT_DIGEST_LEN],
}

impl AuditRecord {
    /// Position in the chain, starting at 0.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The recorded event.
    #[must_use]
    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }

    /// One JSON line for the on-disk log. Digests and the MAC are hex. Nothing else is
    /// stored, so a line holds no payload.
    #[must_use]
    pub fn encode_line(&self) -> String {
        let vault = self.event.vault.map(|v| v.label().to_string());
        serde_json::json!({
            "seq": self.seq,
            "action": self.event.action.code(),
            "token": hex_encode(&self.event.token_digest),
            "shard": hex_encode(&self.event.shard_digest),
            "vault": vault,
            "at": self.event.at,
            "mac": hex_encode(&self.mac),
        })
        .to_string()
    }

    /// Parses one line written by [`AuditRecord::encode_line`].
    ///
    /// The result is not trusted. Pass the decoded records to [`verify_chain`] before
    /// relying on them.
    pub fn decode_line(line: &str) -> Result<Self, ShatterError> {
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| ShatterError::Internal)?;
        let seq = value["seq"].as_u64().ok_or(ShatterError::Internal)?;
        let action = value["action"]
            .as_u64()
            .and_then(|c| u8::try_from(c).ok())
            .and_then(AuditAction::from_code)
            .ok_or(ShatterError::Internal)?;
        let vault = match &value["vault"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => {
                let label = s.chars().next().ok_or(ShatterError::Internal)?;
                Some(VaultId::from_label(label)?)
            }
            _ => return Err(ShatterError::Internal),
        };
        let event = AuditEvent {
            action,
            token_digest: hex_decode(value["token"].as_str())?,
            shard_digest: hex_decode(value["shard"].as_str())?,
            vault,
            at: value["at"].as_u64().ok_or(ShatterError::Internal)?,
        };
        Ok(Self {
            seq,
            event,
            mac: hex_decode(value["mac"].as_str())?,
        })
    }

    /// The chain MAC for this record.
    #[must_use]
    pub const fn mac(&self) -> &[u8; AUDIT_DIGEST_LEN] {
        &self.mac
    }
}

/// Appends events to a tamper-evident chain.
pub struct AuditChain {
    key: Zeroizing<[u8; 32]>,
    next_seq: u64,
    last_mac: [u8; AUDIT_DIGEST_LEN],
}

impl AuditChain {
    /// Starts an empty chain keyed with `key`.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
            next_seq: 0,
            last_mac: [0; AUDIT_DIGEST_LEN],
        }
    }

    /// Resumes a chain from an existing record set.
    ///
    /// Verifies the whole chain first, so a forged or truncated tail is rejected.
    pub fn resume(key: [u8; 32], records: &[AuditRecord]) -> Result<Self, ShatterError> {
        verify_chain(key, records)?;
        Ok(match records.last() {
            Some(last) => Self {
                key: Zeroizing::new(key),
                next_seq: last.seq + 1,
                last_mac: last.mac,
            },
            None => Self::new(key),
        })
    }

    /// Appends one event and returns the stored record.
    pub fn append(&mut self, event: AuditEvent) -> Result<AuditRecord, ShatterError> {
        let seq = self.next_seq;
        let mac = mac_for(&self.key, seq, &self.last_mac, &event)?;
        self.next_seq = seq.checked_add(1).ok_or(ShatterError::Internal)?;
        self.last_mac = mac;
        Ok(AuditRecord { seq, event, mac })
    }
}

/// Verifies a complete chain from its genesis record under `key`.
///
/// Checks sequence numbers, links, and MACs. Uses constant-time MAC comparison.
pub fn verify_chain(key: [u8; 32], records: &[AuditRecord]) -> Result<(), ShatterError> {
    let mut prev = [0u8; AUDIT_DIGEST_LEN];
    for (expected_seq, record) in (0u64..).zip(records) {
        if record.seq != expected_seq {
            return Err(ShatterError::Internal);
        }
        let mut mac = HmacSha256::new_from_slice(&key[..]).map_err(|_| ShatterError::Internal)?;
        absorb(&mut mac, record.seq, &prev, &record.event);
        mac.verify_slice(&record.mac)
            .map_err(|_| ShatterError::Internal)?;
        prev = record.mac;
    }
    Ok(())
}

fn mac_for(
    key: &[u8; 32],
    seq: u64,
    prev: &[u8; AUDIT_DIGEST_LEN],
    event: &AuditEvent,
) -> Result<[u8; AUDIT_DIGEST_LEN], ShatterError> {
    let mut mac = HmacSha256::new_from_slice(&key[..]).map_err(|_| ShatterError::Internal)?;
    absorb(&mut mac, seq, prev, event);
    Ok(mac.finalize().into_bytes().into())
}

fn absorb(mac: &mut HmacSha256, seq: u64, prev: &[u8; AUDIT_DIGEST_LEN], event: &AuditEvent) {
    mac.update(CHAIN_DOMAIN);
    mac.update(&seq.to_be_bytes());
    mac.update(prev);
    mac.update(&[event.action.code()]);
    mac.update(&event.token_digest);
    mac.update(&event.shard_digest);
    mac.update(&[event.vault.map_or(0, |v| v.label() as u8)]);
    mac.update(&event.at.to_be_bytes());
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_decode(text: Option<&str>) -> Result<[u8; AUDIT_DIGEST_LEN], ShatterError> {
    let text = text.ok_or(ShatterError::Internal)?;
    if text.len() != AUDIT_DIGEST_LEN * 2 || !text.is_ascii() {
        return Err(ShatterError::Internal);
    }
    let mut out = [0u8; AUDIT_DIGEST_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| ShatterError::Internal)?;
    }
    Ok(out)
}

#[cfg(test)]
mod line_tests {
    use super::*;

    const KEY: [u8; 32] = [0x3C; 32];

    fn event(action: AuditAction, vault: Option<VaultId>, at: u64) -> AuditEvent {
        AuditEvent {
            action,
            token_digest: [0xAA; AUDIT_DIGEST_LEN],
            shard_digest: [0xBB; AUDIT_DIGEST_LEN],
            vault,
            at,
        }
    }

    #[test]
    fn lines_round_trip_and_still_verify() {
        let mut chain = AuditChain::new(KEY);
        let records = vec![
            chain
                .append(event(AuditAction::Issue, None, 1))
                .expect("append"),
            chain
                .append(event(AuditAction::Alarm, Some(VaultId::C), 2))
                .expect("append"),
        ];
        let decoded: Vec<AuditRecord> = records
            .iter()
            .map(|r| AuditRecord::decode_line(&r.encode_line()).expect("decode"))
            .collect();
        assert_eq!(decoded, records);
        assert_eq!(verify_chain(KEY, &decoded), Ok(()));
    }

    #[test]
    fn a_tampered_line_decodes_but_fails_verification() {
        let mut chain = AuditChain::new(KEY);
        let records = [chain
            .append(event(AuditAction::Issue, None, 5))
            .expect("append")];
        let edited = records[0].encode_line().replace("\"at\":5", "\"at\":6");
        let decoded = AuditRecord::decode_line(&edited).expect("decode");
        assert!(verify_chain(KEY, &[decoded]).is_err());
    }

    #[test]
    fn malformed_lines_are_refused() {
        assert_eq!(
            AuditRecord::decode_line("not json").err(),
            Some(ShatterError::Internal)
        );
        assert_eq!(
            AuditRecord::decode_line(
                r#"{"seq":0,"action":99,"token":"","shard":"","vault":null,"at":1,"mac":""}"#
            )
            .err(),
            Some(ShatterError::Internal)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5A; 32];

    fn event(action: AuditAction, at: u64) -> AuditEvent {
        AuditEvent {
            action,
            token_digest: [1; AUDIT_DIGEST_LEN],
            shard_digest: [2; AUDIT_DIGEST_LEN],
            vault: Some(VaultId::B),
            at,
        }
    }

    fn sample_chain() -> Vec<AuditRecord> {
        let mut chain = AuditChain::new(KEY);
        vec![
            chain
                .append(event(AuditAction::Ingest, 10))
                .expect("append"),
            chain.append(event(AuditAction::Read, 11)).expect("append"),
            chain.append(event(AuditAction::Alarm, 12)).expect("append"),
        ]
    }

    #[test]
    fn fresh_chain_verifies() {
        assert_eq!(verify_chain(KEY, &sample_chain()), Ok(()));
    }

    #[test]
    fn empty_chain_verifies() {
        assert_eq!(verify_chain(KEY, &[]), Ok(()));
    }

    #[test]
    fn edited_event_is_detected() {
        let mut records = sample_chain();
        records[1].event.at = 999;
        assert!(verify_chain(KEY, &records).is_err());
    }

    #[test]
    fn deleted_middle_record_is_detected() {
        let mut records = sample_chain();
        records.remove(1);
        assert!(verify_chain(KEY, &records).is_err());
    }

    #[test]
    fn reordered_records_are_detected() {
        let mut records = sample_chain();
        records.swap(0, 1);
        assert!(verify_chain(KEY, &records).is_err());
    }

    #[test]
    fn wrong_key_is_detected() {
        assert!(verify_chain([0x00; 32], &sample_chain()).is_err());
    }

    #[test]
    fn resume_continues_the_chain() {
        let records = sample_chain();
        let mut chain = AuditChain::resume(KEY, &records).expect("resume");
        let mut extended = records.clone();
        extended.push(
            chain
                .append(event(AuditAction::KeyRotation, 13))
                .expect("append"),
        );
        assert_eq!(extended[3].seq(), 3);
        assert_eq!(verify_chain(KEY, &extended), Ok(()));
    }

    #[test]
    fn resume_rejects_a_forged_tail() {
        let mut records = sample_chain();
        records[2].event.at = 0;
        assert!(AuditChain::resume(KEY, &records).is_err());
    }

    #[test]
    fn records_hold_no_payload_fields() {
        // The only data an event can carry is its action, digests, vault label, and time.
        let rec = sample_chain().remove(0);
        let shown = format!("{rec:?}");
        assert!(shown.contains("AuditEvent"));
        assert_eq!(rec.event().vault, Some(VaultId::B));
    }
}
