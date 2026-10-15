// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Canary (honeytoken) records, detection, and alarm handling.
//!
//! [`CanaryPlan`] derives synthetic records and their shard keys from a secret, so
//! they can be injected with the normal shredder. [`Detector`] recognizes a canary
//! FragmentId in a set of queried IDs. [`AlarmGate`] turns detections into one
//! response: rotate the signing key, notify security, then disarm until a human re-arms.
//!
//! [`CanaryRotation`] gives the plan for the current epoch and says when a refresh is
//! due. [`Alarm::record`] writes a detection to the security alert log, which is the
//! notification channel.
//!
//! Canary values are shaped by field name (see [`values`]), so a canary record looks like
//! a real one to someone who reads a vault.

use std::collections::HashMap;

/// Re-exported from `tpt-shatter-common`, so the gateway can respond to alarms without
/// depending on this crate.
pub use tpt_shatter_common::{Alarm, Responder};
use tpt_shatter_common::{
    FragmentId, Record, SHARD_KEY_LEN, ShardKey, ShatterError, ShatterSchema, VaultId,
};
use tpt_shatter_vault_client::{derive_fragment_id, keyed_digest};
use zeroize::Zeroizing;

mod ids;
mod inject;
mod monitor;
mod rotation;
mod values;
mod watch;

pub use ids::CanaryIds;
pub use inject::refresh_canaries;
pub use monitor::CanaryMonitor;
pub use rotation::CanaryRotation;
pub use watch::CanaryWatch;

const SHARD_DOMAIN: &[u8] = b"tpt-shatter/canary/shard/v1";
const PREFIX_DOMAIN: &[u8] = b"tpt-shatter/canary/prefix/v1";
const EPOCH_DOMAIN: &[u8] = b"tpt-shatter/canary/epoch/v1";
const VALUE_DOMAIN: &[u8] = b"tpt-shatter/canary/value/v1";

/// Describes the canaries to inject: count, shard keys, and value prefix.
///
/// The canary key is separate from the derivation key. Holding the canary key lets
/// you recognize canaries, but it does not let you reach real data.
pub struct CanaryPlan {
    canary_key: Zeroizing<[u8; 32]>,
    derivation_key: Zeroizing<[u8; 32]>,
    count: usize,
}

impl CanaryPlan {
    /// Creates a plan for `count` canaries. `count` must be positive.
    pub fn new(
        canary_key: [u8; 32],
        derivation_key: [u8; 32],
        count: usize,
    ) -> Result<Self, ShatterError> {
        if count == 0 {
            return Err(ShatterError::InvalidParameter);
        }
        Ok(Self {
            canary_key: Zeroizing::new(canary_key),
            derivation_key: Zeroizing::new(derivation_key),
            count,
        })
    }

    /// Builds the plan for one rotation epoch. The canary key is derived from
    /// `master_key` and `epoch`, so each epoch yields fresh canaries while the
    /// master key stays fixed. Canaries from an old epoch stop matching.
    pub fn for_epoch(
        master_key: [u8; 32],
        derivation_key: [u8; 32],
        count: usize,
        epoch: u64,
    ) -> Result<Self, ShatterError> {
        let canary_key = keyed_digest(&master_key[..], EPOCH_DOMAIN, &epoch.to_be_bytes())?;
        Self::new(canary_key, derivation_key, count)
    }

    /// Number of canaries in the plan.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Every canary FragmentId as `(vault, canary index, FragmentId)`. Holds no key, so it
    /// is what a detector needs without the canary key.
    pub fn fragment_ids(&self) -> Result<Vec<(VaultId, usize, FragmentId)>, ShatterError> {
        let mut out = Vec::with_capacity(self.count * VaultId::ALL.len());
        for index in 0..self.count {
            let shard = self.shard(index)?;
            for vault in VaultId::ALL {
                let id = derive_fragment_id(&self.derivation_key[..], &shard, vault)?;
                out.push((vault, index, id));
            }
        }
        Ok(out)
    }

    /// The secret 8-hex-digit prefix that marks every canary value.
    pub fn prefix(&self) -> Result<String, ShatterError> {
        let digest = keyed_digest(&self.canary_key[..], PREFIX_DOMAIN, &[])?;
        Ok(digest[..4].iter().map(|b| format!("{b:02x}")).collect())
    }

    /// The shard key for canary `index`. Deterministic, so the same plan always yields the same canary.
    pub fn shard(&self, index: usize) -> Result<ShardKey, ShatterError> {
        if index >= self.count {
            return Err(ShatterError::InvalidParameter);
        }
        let digest = keyed_digest(
            &self.canary_key[..],
            SHARD_DOMAIN,
            &(index as u64).to_be_bytes(),
        )?;
        Ok(ShardKey::from_bytes(digest))
    }

    /// The canary record for `index`, with a realistic value in every schema field.
    ///
    /// Each value is derived from the canary key, the index, and the field name, so only
    /// holders of the canary key can reproduce it. The shape follows the field name; see
    /// [`values::canary_value`].
    pub fn record(&self, schema: &ShatterSchema, index: usize) -> Result<Record, ShatterError> {
        let mut record = Record::new();
        for vault in VaultId::ALL {
            for field in schema.fields_for(vault) {
                let seed = keyed_digest(
                    &self.canary_key[..],
                    VALUE_DOMAIN,
                    format!("{index}/{field}").as_bytes(),
                )?;
                record.insert(field, values::canary_value(field, &seed));
            }
        }
        Ok(record)
    }
}

/// The rotation epoch containing `now`, for epochs of `period_secs` seconds.
///
/// Pass the result to [`CanaryPlan::for_epoch`]. A zero period is rejected.
pub const fn epoch_at(now: u64, period_secs: u64) -> Result<u64, ShatterError> {
    if period_secs == 0 {
        return Err(ShatterError::InvalidParameter);
    }
    Ok(now / period_secs)
}

/// Recognizes canary FragmentIds among queried IDs.
pub struct Detector {
    index: HashMap<(VaultId, [u8; SHARD_KEY_LEN]), usize>,
}

impl Detector {
    /// Precomputes every canary FragmentId in every vault.
    pub fn new(plan: &CanaryPlan) -> Result<Self, ShatterError> {
        Ok(Self::from_entries(&plan.fragment_ids()?))
    }

    /// Detects the given canary FragmentIds, as listed by [`CanaryIds`]. Needs no key.
    #[must_use]
    pub fn from_entries(entries: &[(VaultId, usize, FragmentId)]) -> Self {
        let index = entries
            .iter()
            .map(|(vault, canary, id)| ((*vault, *id.as_bytes()), *canary))
            .collect();
        Self { index }
    }

    /// Returns one alarm for each queried ID that matches a canary.
    ///
    /// The lookup is a hash map probe, not a constant-time comparison. Canary IDs are
    /// derived from a secret, so this is acceptable for detection. It is not a
    /// secret-comparison primitive.
    #[must_use]
    pub fn scan(&self, queries: &[(VaultId, FragmentId)]) -> Vec<Alarm> {
        queries
            .iter()
            .filter_map(|(vault, id)| {
                self.index
                    .get(&(*vault, *id.as_bytes()))
                    .map(|index| Alarm {
                        vault: *vault,
                        index: *index,
                    })
            })
            .collect()
    }
}

/// What an [`AlarmGate::handle`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No canaries were touched.
    Quiet,
    /// The response ran for these alarms. The gate is now disarmed.
    Fired {
        /// Alarms covered by this response.
        alarms: usize,
    },
    /// The gate is disarmed, so these alarms were recorded but did not trigger a response.
    Suppressed {
        /// Alarms that were suppressed.
        alarms: usize,
    },
}

/// Fires the response once, then disarms until a human re-arms it.
///
/// This stops a flood of canary hits from producing a flood of key rotations. If the
/// response fails partway, the gate stays armed, so the next detection retries it.
pub struct AlarmGate {
    cooldown_secs: u64,
    armed: bool,
    last_fired: Option<u64>,
}

impl AlarmGate {
    /// Creates an armed gate. After it fires, re-arming waits `cooldown_secs`.
    #[must_use]
    pub const fn new(cooldown_secs: u64) -> Self {
        Self {
            cooldown_secs,
            armed: true,
            last_fired: None,
        }
    }

    /// Whether the gate will respond to the next alarm.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Handles a batch of alarms at time `now` (Unix seconds).
    pub fn handle(
        &mut self,
        alarms: &[Alarm],
        now: u64,
        responder: &dyn Responder,
    ) -> Result<Outcome, ShatterError> {
        if alarms.is_empty() {
            return Ok(Outcome::Quiet);
        }
        if !self.armed {
            return Ok(Outcome::Suppressed {
                alarms: alarms.len(),
            });
        }
        responder.rotate_signing_key()?;
        for alarm in alarms {
            responder.notify_security(alarm)?;
        }
        self.armed = false;
        self.last_fired = Some(now);
        Ok(Outcome::Fired {
            alarms: alarms.len(),
        })
    }

    /// Re-arms the gate. Refused until the cooldown since the last firing has passed.
    ///
    /// Returns [`ShatterError::InvalidParameter`] if called too soon.
    pub fn rearm(&mut self, now: u64) -> Result<(), ShatterError> {
        if self.armed {
            return Ok(());
        }
        let ready_at = self
            .last_fired
            .unwrap_or(0)
            .saturating_add(self.cooldown_secs);
        if now < ready_at {
            return Err(ShatterError::InvalidParameter);
        }
        self.armed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tpt_shatter_common::{AlertLog, SHARD_KEY_LEN};

    const CANARY_KEY: [u8; 32] = [0xC1; 32];
    const DERIVATION_KEY: [u8; 32] = [0xD2; 32];

    fn plan(count: usize) -> CanaryPlan {
        CanaryPlan::new(CANARY_KEY, DERIVATION_KEY, count).expect("plan")
    }

    fn schema() -> ShatterSchema {
        ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("schema")
    }

    /// Counts calls and can be made to fail.
    struct Recorder {
        rotations: Cell<u32>,
        notifications: Cell<u32>,
        fail_rotation: Cell<bool>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                rotations: Cell::new(0),
                notifications: Cell::new(0),
                fail_rotation: Cell::new(false),
            }
        }
    }

    impl Responder for Recorder {
        fn rotate_signing_key(&self) -> Result<(), ShatterError> {
            if self.fail_rotation.get() {
                return Err(ShatterError::Internal);
            }
            self.rotations.set(self.rotations.get() + 1);
            Ok(())
        }
        fn notify_security(&self, _: &Alarm) -> Result<(), ShatterError> {
            self.notifications.set(self.notifications.get() + 1);
            Ok(())
        }
    }

    fn canary_fragments(plan: &CanaryPlan, index: usize) -> Vec<(VaultId, FragmentId)> {
        let shard = plan.shard(index).expect("shard");
        VaultId::ALL
            .iter()
            .map(|v| {
                (
                    *v,
                    derive_fragment_id(&DERIVATION_KEY, &shard, *v).expect("id"),
                )
            })
            .collect()
    }

    #[test]
    fn epochs_rotate_canaries_deterministically() {
        let a = CanaryPlan::for_epoch(CANARY_KEY, DERIVATION_KEY, 2, 7).expect("plan");
        let a_again = CanaryPlan::for_epoch(CANARY_KEY, DERIVATION_KEY, 2, 7).expect("plan");
        let b = CanaryPlan::for_epoch(CANARY_KEY, DERIVATION_KEY, 2, 8).expect("plan");
        assert_eq!(a.prefix().expect("p"), a_again.prefix().expect("p"));
        assert_eq!(
            a.shard(0).expect("s").as_bytes(),
            a_again.shard(0).expect("s").as_bytes()
        );
        assert_ne!(a.prefix().expect("p"), b.prefix().expect("p"));
        assert_ne!(
            a.shard(0).expect("s").as_bytes(),
            b.shard(0).expect("s").as_bytes()
        );
    }

    #[test]
    fn epoch_at_buckets_time_and_rejects_zero_period() {
        assert_eq!(epoch_at(0, 3600), Ok(0));
        assert_eq!(epoch_at(3599, 3600), Ok(0));
        assert_eq!(epoch_at(3600, 3600), Ok(1));
        assert_eq!(epoch_at(10, 0), Err(ShatterError::InvalidParameter));
    }

    #[test]
    fn plan_is_deterministic_and_secret_dependent() {
        let p = plan(3);
        assert_eq!(p.prefix().expect("a"), plan(3).prefix().expect("b"));
        let other = CanaryPlan::new([0xEE; 32], DERIVATION_KEY, 3).expect("other");
        assert_ne!(p.prefix().expect("a"), other.prefix().expect("b"));
        assert_eq!(p.prefix().expect("p").len(), 8);
        assert_eq!(p.shard(1).expect("s").as_bytes().len(), SHARD_KEY_LEN);
        assert!(p.shard(3).is_err());
        assert!(CanaryPlan::new(CANARY_KEY, DERIVATION_KEY, 0).is_err());
    }

    #[test]
    fn canary_record_fills_every_field_with_a_shaped_value() {
        let p = plan(2);
        let r = p.record(&schema(), 1).expect("record");
        assert_eq!(r.len(), 3);
        assert!(r.get("name").expect("name").contains(' '));
        let year: u32 = r.get("birth_year").expect("year").parse().expect("number");
        assert!((1940..=2005).contains(&year));
        assert_eq!(r.get("card_number").expect("card").len(), 16);
    }

    #[test]
    fn canary_values_depend_on_the_canary_key_and_index() {
        let p = plan(2);
        let other_key = CanaryPlan::new([0xEE; 32], DERIVATION_KEY, 2).expect("other");
        let a = p.record(&schema(), 0).expect("record");
        let b = p.record(&schema(), 1).expect("record");
        let c = other_key.record(&schema(), 0).expect("record");
        assert_ne!(a.get("name"), b.get("name"));
        assert_ne!(a.get("name"), c.get("name"));
        // Same key and index always give the same record.
        let again = p.record(&schema(), 0).expect("record");
        assert_eq!(a.get("card_number"), again.get("card_number"));
    }

    #[test]
    fn detector_finds_canary_fragments_only() {
        let p = plan(4);
        let detector = Detector::new(&p).expect("detector");
        let hits = detector.scan(&canary_fragments(&p, 2));
        assert_eq!(hits.len(), 3);
        assert!(hits.iter().all(|a| a.index == 2));

        let real_shard = ShardKey::from_bytes([0x55; SHARD_KEY_LEN]);
        let real: Vec<_> = VaultId::ALL
            .iter()
            .map(|v| {
                (
                    *v,
                    derive_fragment_id(&DERIVATION_KEY, &real_shard, *v).expect("id"),
                )
            })
            .collect();
        assert!(detector.scan(&real).is_empty());
    }

    #[test]
    fn alarm_is_written_to_the_alert_log_with_only_vault_and_index() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("tpt-shatter-canary-alert-{nanos}.jsonl"));
        let log = AlertLog::open(&path).expect("open");
        Alarm {
            vault: VaultId::C,
            index: 7,
        }
        .record(&log, 1234)
        .expect("record");
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::remove_file(&path).expect("cleanup");
        assert!(text.contains(r#""kind":"canary_alarm""#));
        assert!(text.contains(r#""vault":"C""#));
        assert!(text.contains(r#""index":"7""#));
        assert!(text.contains(r#""at":1234"#));
    }

    #[test]
    fn alarm_debug_has_no_identifiers() {
        let alarm = Alarm {
            vault: VaultId::C,
            index: 7,
        };
        let shown = format!("{alarm:?}");
        assert!(shown.contains("index: 7"));
        assert!(!shown.contains("FragmentId"));
    }

    #[test]
    fn gate_fires_once_then_suppresses() {
        let p = plan(2);
        let detector = Detector::new(&p).expect("detector");
        let alarms = detector.scan(&canary_fragments(&p, 0));
        let responder = Recorder::new();
        let mut gate = AlarmGate::new(600);

        assert_eq!(
            gate.handle(&alarms, 100, &responder),
            Ok(Outcome::Fired { alarms: 3 })
        );
        assert_eq!(responder.rotations.get(), 1);
        assert_eq!(responder.notifications.get(), 3);
        assert!(!gate.is_armed());

        assert_eq!(
            gate.handle(&alarms, 101, &responder),
            Ok(Outcome::Suppressed { alarms: 3 })
        );
        assert_eq!(responder.rotations.get(), 1, "no second rotation");
    }

    #[test]
    fn quiet_scans_do_nothing() {
        let responder = Recorder::new();
        let mut gate = AlarmGate::new(600);
        assert_eq!(gate.handle(&[], 0, &responder), Ok(Outcome::Quiet));
        assert_eq!(responder.rotations.get(), 0);
    }

    #[test]
    fn failed_response_keeps_the_gate_armed_for_retry() {
        let p = plan(1);
        let alarms = Detector::new(&p)
            .expect("detector")
            .scan(&canary_fragments(&p, 0));
        let responder = Recorder::new();
        responder.fail_rotation.set(true);
        let mut gate = AlarmGate::new(600);
        assert!(gate.handle(&alarms, 0, &responder).is_err());
        assert!(gate.is_armed());

        responder.fail_rotation.set(false);
        assert_eq!(
            gate.handle(&alarms, 1, &responder),
            Ok(Outcome::Fired { alarms: 3 })
        );
    }

    #[test]
    fn rearm_waits_for_the_cooldown() {
        let p = plan(1);
        let alarms = Detector::new(&p)
            .expect("detector")
            .scan(&canary_fragments(&p, 0));
        let responder = Recorder::new();
        let mut gate = AlarmGate::new(600);
        gate.handle(&alarms, 1_000, &responder).expect("fire");

        assert_eq!(gate.rearm(1_599), Err(ShatterError::InvalidParameter));
        assert!(!gate.is_armed());
        gate.rearm(1_600).expect("rearm after cooldown");
        assert!(gate.is_armed());
    }
}
