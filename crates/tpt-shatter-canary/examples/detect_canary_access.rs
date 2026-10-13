// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Plants canary records in the vaults, watches the router, and shows what happens when a
//! canary is read: the alarm is queued, the response runs once, and the event is written to
//! the security alert log.
//!
//! Run with: `cargo run -p tpt-shatter-canary --example detect_canary_access`

use std::fs;
use std::sync::Arc;

use tpt_shatter_canary::{
    Alarm, CanaryMonitor, CanaryRotation, CanaryWatch, Responder, refresh_canaries,
};
use tpt_shatter_common::{AlertLog, SHARD_KEY_LEN, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_vault_client::{
    BreakerConfig, Guarded, MemoryVault, Router, derive_fragment_id, system_clock,
};

const DERIVATION_KEY: [u8; 32] = [0xA1; 32];

/// The response to a canary alarm. A real deployment rotates the token signing key and
/// pages the security team here. This example just prints what it would do.
struct PrintingResponder;

impl Responder for PrintingResponder {
    fn rotate_signing_key(&self) -> Result<(), ShatterError> {
        println!("  response: rotate the token signing key");
        Ok(())
    }

    fn notify_security(&self, alarm: &Alarm) -> Result<(), ShatterError> {
        // The alarm carries only the vault and the canary index. No identifiers, no values.
        println!(
            "  response: notify security (vault {}, canary {})",
            alarm.vault, alarm.index
        );
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = ShatterSchema::new(
        1,
        [
            ("name", VaultId::A),
            ("birth_year", VaultId::B),
            ("card_number", VaultId::C),
        ],
    )?;

    // Rotation: three canaries per epoch, a new set every hour. The master key is a secret.
    let rotation = CanaryRotation::new([0xB2; 32], DERIVATION_KEY, 3, 3_600)?;
    let now: u64 = 1_700_000_000;

    // The watch must know the current canaries before any read happens, so build it from
    // the plan for this epoch and attach it to the router as an observer.
    let plan = rotation.plan_at(now)?;
    let watch = Arc::new(CanaryWatch::new(&plan)?);
    let guards = VaultId::ALL
        .into_iter()
        .map(|v| {
            Guarded::new(
                Box::new(MemoryVault::new(v)),
                BreakerConfig::default(),
                system_clock(),
            )
        })
        .collect();
    let router = Router::new(guards)?.with_observer(watch.clone());

    // Plant the canaries. Writes are not observed, so planting does not raise an alarm.
    let last = refresh_canaries(&rotation, &schema, &router, &DERIVATION_KEY, None, now)?;
    println!("planted canaries for epoch {last:?}");

    // Ordinary traffic does not trip the watch. Reads of a real shard are not canary reads.
    let real_shard = ShardKey::from_bytes([0x99; SHARD_KEY_LEN]);
    let real_id = derive_fragment_id(&DERIVATION_KEY, &real_shard, VaultId::A)?;
    let _ = router.get(VaultId::A, &real_id)?;
    println!("alarms after a normal read: {}", watch.take_alarms()?.len());

    // Someone reads canary 1 in vault B. The router reports the access to the watch.
    let canary_shard = plan.shard(1)?;
    let canary_id = derive_fragment_id(&DERIVATION_KEY, &canary_shard, VaultId::B)?;
    let _ = router.get(VaultId::B, &canary_id)?;

    // The monitor drains the watch, runs the response at most once per cooldown, and writes
    // each alarm to the alert log.
    let alert_path = std::env::temp_dir().join("tpt-shatter-example-alerts.jsonl");
    let _ = fs::remove_file(&alert_path);
    let mut monitor = CanaryMonitor::new(watch.clone(), 300, AlertLog::open(&alert_path)?);
    println!("canary read detected, running the response:");
    let outcome = monitor.poll(&PrintingResponder, now + 5)?;
    println!("outcome: {outcome:?}");

    // A second read inside the cooldown is recorded, but the response does not run again.
    let _ = router.get(VaultId::B, &canary_id)?;
    let outcome = monitor.poll(&PrintingResponder, now + 10)?;
    println!("second read within cooldown, outcome: {outcome:?}");

    println!("alert log written to {}", alert_path.display());
    let _ = fs::remove_file(&alert_path);

    // The canary record itself is shaped like a real one, so it looks plausible to a reader.
    let sample = plan.record(&schema, 0)?;
    let fields: Vec<&str> = sample.field_names().collect();
    println!("canary record fields: {fields:?}");

    Ok(())
}
