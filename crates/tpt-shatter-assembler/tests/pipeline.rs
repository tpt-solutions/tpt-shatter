// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! End-to-end pipeline: shred -> vaults -> assemble -> emit, with canary detection and erasure.
//! Uses synthetic data only.

use std::sync::Arc;

use std::cell::Cell;
use tpt_shatter_assembler::Assembler;
use tpt_shatter_canary::{AlarmGate, CanaryPlan, Detector, Outcome, Responder};
use tpt_shatter_common::{Record, SHARD_KEY_LEN, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_emitter::{Emitter, MemorySink, Policy, Transform};
use tpt_shatter_shredder::{Shredder, erase};
use tpt_shatter_vault_client::{
    BreakerConfig, Guarded, MemoryVault, Router, decode_fields, derive_fragment_id, system_clock,
};

const DERIVATION_KEY: [u8; 32] = [0xA1; 32];
const CANARY_KEY: [u8; 32] = [0xB2; 32];
const RAW_NAME: &str = "Synthetic Person";
const RAW_CARD: &str = "4000000000000002";

struct Stack {
    schema: ShatterSchema,
    router: Router,
    vaults: Vec<Arc<MemoryVault>>,
}

fn stack() -> Stack {
    let schema = ShatterSchema::new(
        1,
        [
            ("name", VaultId::A),
            ("birth_year", VaultId::B),
            ("card_number", VaultId::C),
        ],
    )
    .expect("schema");
    let vaults: Vec<Arc<MemoryVault>> = VaultId::ALL
        .iter()
        .map(|v| Arc::new(MemoryVault::new(*v)))
        .collect();
    let guards = vaults
        .iter()
        .map(|v| {
            Guarded::new(
                Box::new(Arc::clone(v)),
                BreakerConfig {
                    attempts: 1,
                    ..BreakerConfig::default()
                },
                system_clock(),
            )
        })
        .collect();
    Stack {
        schema,
        router: Router::new(guards).expect("router"),
        vaults,
    }
}

fn person(name: &str, year: &str) -> Record {
    let mut r = Record::new();
    r.insert("name", name);
    r.insert("birth_year", year);
    r.insert("card_number", RAW_CARD);
    r
}

fn shard(byte: u8) -> ShardKey {
    ShardKey::from_bytes([byte; SHARD_KEY_LEN])
}

fn policy(k: usize) -> Policy {
    Policy::new(
        b"pipeline-salt".to_vec(),
        [
            ("name".to_owned(), Transform::Pseudonymize),
            ("birth_year".to_owned(), Transform::Bucket { width: 10 }),
            ("card_number".to_owned(), Transform::Mask { keep_last: 4 }),
        ],
        vec!["birth_year".to_owned()],
        k,
    )
    .expect("policy")
}

#[derive(Default)]
struct CountingResponder {
    rotations: Cell<u32>,
    notifications: Cell<u32>,
}

impl Responder for CountingResponder {
    fn rotate_signing_key(&self) -> Result<(), ShatterError> {
        self.rotations.set(self.rotations.get() + 1);
        Ok(())
    }
    fn notify_security(&self, _: &tpt_shatter_canary::Alarm) -> Result<(), ShatterError> {
        self.notifications.set(self.notifications.get() + 1);
        Ok(())
    }
}

#[test]
fn full_pipeline_round_trip_places_fragments_correctly() {
    let s = stack();
    let key = shard(0x10);

    Shredder::new(&s.schema, &s.router, DERIVATION_KEY)
        .shred(&key, person(RAW_NAME, "1994"))
        .expect("shred");

    // Placement: each vault holds exactly one fragment, and it decodes to its own fields only.
    for (index, vault) in VaultId::ALL.into_iter().enumerate() {
        assert_eq!(s.vaults[index].row_count(), Ok(1), "{vault}");
        let id = derive_fragment_id(&DERIVATION_KEY, &key, vault).expect("id");
        let body = s.router.get(vault, &id).expect("get").expect("present");
        for (name, _) in decode_fields(&body).expect("decode") {
            assert_eq!(s.schema.vault_for(&name), Some(vault), "{name} in {vault}");
        }
    }

    let rebuilt = Assembler::new(&s.schema, &s.router, DERIVATION_KEY)
        .assemble(&key)
        .expect("assemble");
    assert_eq!(rebuilt.get("name"), Some(RAW_NAME));
    assert_eq!(rebuilt.get("birth_year"), Some("1994"));
    assert_eq!(rebuilt.get("card_number"), Some(RAW_CARD));
}

#[test]
fn emitted_analytics_contain_no_raw_identifiers() {
    let s = stack();
    let key = shard(0x20);
    Shredder::new(&s.schema, &s.router, DERIVATION_KEY)
        .shred(&key, person(RAW_NAME, "1994"))
        .expect("shred");
    let rebuilt = Assembler::new(&s.schema, &s.router, DERIVATION_KEY)
        .assemble(&key)
        .expect("assemble");

    let emitter = Emitter::new(policy(1), MemorySink::new());
    let report = emitter.emit(vec![rebuilt]).expect("emit");
    assert_eq!(report.emitted, 1);

    let events = emitter.sink().events().expect("events");
    assert_eq!(events.len(), 1);
    let shown = format!("{events:?}");
    assert!(!shown.contains(RAW_NAME));
    assert!(!shown.contains("4000000000000002"));
    assert_eq!(events[0].get("birth_year"), Some("1990-1999"));
    assert_eq!(events[0].get("card_number"), Some("************0002"));
}

#[test]
fn canary_touch_fires_one_response_and_no_values_leak() {
    let s = stack();
    let plan = CanaryPlan::new(CANARY_KEY, DERIVATION_KEY, 2).expect("plan");
    let shredder = Shredder::new(&s.schema, &s.router, DERIVATION_KEY);
    for index in 0..plan.count() {
        shredder
            .shred(
                &plan.shard(index).expect("shard"),
                plan.record(&s.schema, index).expect("record"),
            )
            .expect("inject canary");
    }

    // An attacker queries canary 1 in vault B.
    let canary_shard = plan.shard(1).expect("shard");
    let touched = derive_fragment_id(&DERIVATION_KEY, &canary_shard, VaultId::B).expect("id");
    let detector = Detector::new(&plan).expect("detector");
    let alarms = detector.scan(&[(VaultId::B, touched)]);
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].index, 1);
    assert!(!format!("{alarms:?}").contains(&plan.prefix().expect("prefix")));

    let responder = CountingResponder::default();
    let mut gate = AlarmGate::new(600);
    assert_eq!(
        gate.handle(&alarms, 1_000, &responder),
        Ok(Outcome::Fired { alarms: 1 })
    );
    assert_eq!(responder.rotations.get(), 1);
    assert_eq!(responder.notifications.get(), 1);

    // A second touch is recorded but does not rotate the key again.
    assert_eq!(
        gate.handle(&alarms, 1_001, &responder),
        Ok(Outcome::Suppressed { alarms: 1 })
    );
    assert_eq!(responder.rotations.get(), 1);
}

#[test]
fn partial_write_leaves_no_orphan_across_vaults() {
    let s = stack();
    s.vaults[2].set_available(false);
    let key = shard(0x30);
    let result =
        Shredder::new(&s.schema, &s.router, DERIVATION_KEY).shred(&key, person(RAW_NAME, "1994"));
    assert_eq!(
        result,
        Err(ShatterError::VaultUnavailable { vault: VaultId::C })
    );
    assert_eq!(s.vaults[0].row_count(), Ok(0));
    assert_eq!(s.vaults[1].row_count(), Ok(0));
}

#[test]
fn erased_subject_cannot_be_reassembled() {
    let s = stack();
    let key = shard(0x40);
    Shredder::new(&s.schema, &s.router, DERIVATION_KEY)
        .shred(&key, person(RAW_NAME, "1994"))
        .expect("shred");
    let report = erase(&s.router, &DERIVATION_KEY, &key).expect("erase");
    assert!(report.verified);
    assert_eq!(report.rows_removed, 3);
    assert_eq!(
        Assembler::new(&s.schema, &s.router, DERIVATION_KEY)
            .assemble(&key)
            .err(),
        Some(ShatterError::Reconstruction)
    );
}

#[test]
fn vault_outage_during_read_fails_closed() {
    let s = stack();
    let key = shard(0x50);
    Shredder::new(&s.schema, &s.router, DERIVATION_KEY)
        .shred(&key, person(RAW_NAME, "1994"))
        .expect("shred");
    s.vaults[1].set_available(false);
    assert_eq!(
        Assembler::new(&s.schema, &s.router, DERIVATION_KEY)
            .assemble(&key)
            .err(),
        Some(ShatterError::VaultUnavailable { vault: VaultId::B })
    );
}
