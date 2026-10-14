// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `tpt-shatter-gateway <config.json>`: serves the public read path until stopped.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use tpt_shatter_gateway_service::{GatewayConfig, run};

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: tpt-shatter-gateway <config.json>");
        return ExitCode::FAILURE;
    };
    match load_and_run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tpt-shatter-gateway: {message}");
            ExitCode::FAILURE
        }
    }
}

fn load_and_run(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|_| "config: unreadable".to_owned())?;
    let config = GatewayConfig::from_json(&text)?;
    run(&config)
}
