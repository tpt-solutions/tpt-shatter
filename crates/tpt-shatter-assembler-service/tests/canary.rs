// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Canary detection on the assembler: a canary read locks the source, a rejected list is
//! logged, and a stale list is logged once without locking. Uses in-memory vaults and
//! synthetic data only.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tpt_shatter_assembler_service::canary::Freshness;
use tpt_shatter_assembler_service::{AssemblerSource, CanaryWatcher, LockedSource};
use tpt_shatter_canary::{CanaryIds, CanaryRotation, CanaryWatch, refresh_canaries};
use tpt_shatter_common::{SHARD_KEY_LEN, ShardKey, ShatterError, ShatterSchema, VaultId};
use tpt_shatter_gateway::RecordSource;
use tpt_shatter_vault_client::{
    AccessObserver, BreakerConfig, Guarded, MemoryVault, Router, system_clock,
};

const MASTER: [u8; 32] = [0xB1; 32];
const DERIVATION: [u8; 32] = [0xB2; 32];
const WEEK: u64 = 7 * 24 * 3600;
const NOW: u64 = 50 * WEEK + 7;
const GRACE: u64 = 600;

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

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tpt-assembler-canary-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("dir");
    dir
}

/// A router over memory vaults, with `watch` attached as its observer.
fn watched_router(watch: &Arc<CanaryWatch>) -> Arc<Router> {
    let guards = VaultId::ALL
        .iter()
        .map(|vault| {
            Guarded::new(
                Box::new(MemoryVault::new(*vault)),
                BreakerConfig {
                    attempts: 1,
                    ..BreakerConfig::default()
                },
                system_clock(),
            )
        })
        .collect();
    let observer: Arc<dyn AccessObserver> = Arc::clone(watch) as Arc<dyn AccessObserver>;
    Arc::new(Router::new(guards).expect("router").with_observer(observer))
}

/// Everything one test needs: the node's epoch-50 canaries injected into a watched router, a
/// locked source over that router, and a watcher reading the list from `dir`.
struct Rig {
    rotation: CanaryRotation,
    plan: tpt_shatter_canary::CanaryPlan,
    source: LockedSource,
    locked: Arc<AtomicBool>,
    watcher: CanaryWatcher,
    alerts: PathBuf,
    list: PathBuf,
}

fn rig(name: &str) -> Rig {
    let rotation = CanaryRotation::new(MASTER, DERIVATION, 2, WEEK).expect("rotation");
    let epoch = rotation.epoch(NOW).expect("epoch");
    let plan = rotation.plan_at(NOW).expect("plan");
    let ids = CanaryIds::from_plan(&plan, epoch).expect("ids");
    let dir = temp_dir(name);
    let list = dir.join("canary-ids.txt");
    ids.write_file(&list).expect("write list");

    let watch = Arc::new(CanaryWatch::from_ids(&ids));
    let router = watched_router(&watch);
    refresh_canaries(&rotation, &schema(), &router, &DERIVATION, None, NOW).expect("refresh");

    let locked = Arc::new(AtomicBool::new(false));
    let inner: Arc<dyn RecordSource> = Arc::new(AssemblerSource::new(
        Arc::new(schema()),
        Arc::clone(&router),
        DERIVATION,
        Duration::from_secs(3),
    ));
    let source = LockedSource::new(inner, Arc::clone(&locked));
    let alerts = dir.join("alerts.jsonl");
    let freshness = Freshness {
        period_secs: WEEK,
        grace_secs: GRACE,
    };
    let watcher = CanaryWatcher::new(
        list.clone(),
        &ids,
        watch,
        &alerts,
        Arc::clone(&locked),
        freshness,
    )
    .expect("watcher");
    Rig {
        rotation,
        plan,
        source,
        locked,
        watcher,
        alerts,
        list,
    }
}

#[test]
fn a_canary_read_through_the_source_locks_it_and_refuses_later_reads() {
    let mut rig = rig("lock");
    rig.watcher.pass(NOW).expect("quiet pass");
    assert!(!rig.locked.load(Ordering::SeqCst));

    // Reading a canary through the source is observed by the router's watch.
    let canary = rig.plan.shard(0).expect("shard");
    let _ = rig.source.fetch(&canary);
    rig.watcher.pass(NOW + 1).expect("alarm pass");

    assert!(rig.locked.load(Ordering::SeqCst));
    assert_eq!(
        rig.source.fetch(&canary).err(),
        Some(ShatterError::ServiceUnavailable)
    );
    let log = fs::read_to_string(&rig.alerts).expect("alert log");
    assert!(log.contains("canary_alarm"), "no alarm logged: {log}");
}

#[test]
fn an_older_list_is_refused_and_the_held_canaries_stay_in_force() {
    let mut rig = rig("rollback");
    let older = CanaryIds::from_plan(&rig.rotation.plan_for_epoch(49).expect("older plan"), 49)
        .expect("older ids");

    // An older list is written over the current one. The pass refuses it and logs why.
    older.write_file(&rig.list).expect("write older list");
    assert!(rig.watcher.pass(NOW).is_err());
    let log = fs::read_to_string(&rig.alerts).expect("alert log");
    assert!(
        log.contains("canary_list_rejected"),
        "no rejection logged: {log}"
    );

    // The current epoch's canaries are still watched.
    let canary = rig.plan.shard(1).expect("shard");
    let _ = rig.source.fetch(&canary);
    let _ = rig.watcher.pass(NOW + 1);
    assert!(rig.locked.load(Ordering::SeqCst));
}

#[test]
fn a_stale_list_is_logged_once_and_serving_continues() {
    let mut rig = rig("stale");
    // The epoch ends at 51 * WEEK. The grace runs to 51 * WEEK + GRACE.
    let epoch_end = 51 * WEEK;

    rig.watcher
        .pass(epoch_end + GRACE)
        .expect("pass at the grace limit");
    let log = fs::read_to_string(&rig.alerts).unwrap_or_default();
    assert!(!log.contains("canary_list_stale"), "stale too early: {log}");

    rig.watcher
        .pass(epoch_end + GRACE + 1)
        .expect("first stale pass");
    rig.watcher
        .pass(epoch_end + GRACE + 60)
        .expect("second stale pass");
    let log = fs::read_to_string(&rig.alerts).expect("alert log");
    assert_eq!(log.matches("canary_list_stale").count(), 1, "{log}");
    assert!(!rig.locked.load(Ordering::SeqCst), "stale must not lock");
    // The source still serves. This shard has no fragments, so the read fails for that reason,
    // not the lock's ServiceUnavailable.
    let unknown = ShardKey::from_bytes([0x42; SHARD_KEY_LEN]);
    assert_ne!(
        rig.source.fetch(&unknown).err(),
        Some(ShatterError::ServiceUnavailable)
    );
}
