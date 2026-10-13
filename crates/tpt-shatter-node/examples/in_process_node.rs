// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Boots a whole node in one process: loads a configuration file, reads the seven keys from
//! the environment, writes a record through the shredder, reads it back through the gateway,
//! and refreshes the canaries. Everything lives in a temporary directory that is removed at
//! the end. Synthetic data only.
//!
//! Run with: `cargo run -p tpt-shatter-node --example in_process_node`

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_shatter_common::{Record, Scope, Scopes, ShardKey, ShatterSchema};
use tpt_shatter_node::{KEY_VARS, Keys, Node, load_config};

const SCHEMA: &str = r#"{
    "version": 1,
    "fields": { "name": "A", "birth_year": "B", "card_number": "C" }
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join("tpt-shatter-example-node");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;

    // 1. Schema file. The node loads it at boot, so a bad schema fails before anything opens.
    let schema_path = root.join("schema.json");
    fs::write(&schema_path, SCHEMA)?;
    ShatterSchema::load_json_file(&schema_path)?;

    // 2. Configuration. Here it is written as JSON and loaded back, which is how a real node
    //    starts. `deny_unknown_fields` rejects typos, so a misspelled key is an error.
    let config_path = root.join("node.json");
    fs::write(&config_path, config_json(&root, &schema_path)?)?;
    let config = load_config(&config_path)?;
    println!("config loaded, canary count {}", config.canary_count);

    // 3. Keys. The node reads each one from the environment as 64 hex characters. The lookup
    //    closure stands in for `std::env::var` so this example stays self-contained.
    let env: HashMap<&str, String> = KEY_VARS
        .iter()
        .enumerate()
        .map(|(i, name)| (*name, hex(&[(i as u8 + 1) * 0x11; 32])))
        .collect();
    let keys = Keys::from_lookup(|name| env.get(name).cloned())?;

    // 4. Build the node. This opens the vault directories and wires everything together.
    let node = Node::build(config, keys)?;
    println!("node built");

    // 5. Write a record. The shredder splits it across the vaults, one fragment each.
    let shard = ShardKey::from_bytes([0x42; 32]);
    let mut record = Record::new();
    record.insert("name", "Synthetic Person");
    record.insert("birth_year", "1994");
    record.insert("card_number", "4000000000000002");
    let report = node.shredder().shred(&shard, record)?;
    println!("wrote {} fragments", report.fragments_written);

    // 6. Read it back through the gateway, with a read token for this shard.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let token = node
        .signer()
        .read()
        .map_err(|_| "signer lock poisoned")?
        .issue(&shard, Scopes::from_scopes(&[Scope::Read]), now)?;
    let response = node
        .gateway()
        .read(token.as_str(), &hex(shard.as_bytes()), now * 1_000);
    println!(
        "gateway read: {} {} ({} fields)",
        response.status,
        response.code,
        response.fields.len()
    );

    // 7. Canaries. Refresh is a no-op within an epoch and writes a new set when the epoch moves.
    let refreshed = node.refresh_canaries(now)?;
    println!("canaries refreshed this pass: {refreshed}");

    // 8. Clean up. A real node keeps its directories; this example does not need them.
    drop(node);
    let _ = fs::remove_dir_all(&root);
    println!("temporary node directory removed");
    Ok(())
}

/// Builds the configuration JSON. `serde_json::json!` escapes Windows paths correctly, which
/// hand-written JSON would not.
fn config_json(root: &Path, schema: &Path) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&serde_json::json!({
        "listen": "127.0.0.1:0",
        "allow_plain_http": true,
        "schema": schema.display().to_string(),
        "state_dir": root.join("state").display().to_string(),
        "vault_dirs": {
            "a": root.join("vault-a").display().to_string(),
            "b": root.join("vault-b").display().to_string(),
            "c": root.join("vault-c").display().to_string(),
        },
        "canary_count": 3,
        "canary_period_secs": 604_800,
        "alarm_cooldown_secs": 300,
        "reap_interval_secs": 60,
        "reap_max_attempts": 5,
        "monitor_interval_secs": 30,
        "retention_secs": 31_536_000,
        "purge_interval_secs": 3_600,
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
