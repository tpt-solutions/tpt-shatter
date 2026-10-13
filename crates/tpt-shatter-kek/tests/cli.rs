// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Runs the real `tpt-shatter-kek` binary. The cloud-custody test uses a stand-in key service,
//! a program that reverses its input, so it needs a Unix shell tool and is gated to Unix.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_tpt-shatter-kek");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tpt-kek-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn shares_from(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn shamir_custody_round_trips_through_the_binary() {
    let dir = scratch("shamir");
    let plain = dir.join("plain");
    let generated = run(
        &[
            "generate",
            plain.to_str().unwrap(),
            "TPT_KEY_TOKEN",
            "TPT_KEY_AUDIT",
        ],
        "",
    );
    assert!(generated.status.success(), "{generated:?}");

    let blob = dir.join("keys.blob");
    let sealed = run(
        &["seal", plain.to_str().unwrap(), blob.to_str().unwrap()],
        "",
    );
    assert!(sealed.status.success(), "{sealed:?}");
    let lines: Vec<String> = shares_from(&sealed).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 3, "three custodian shares");

    let boot = dir.join("boot");
    let unsealed = run(
        &["unseal", blob.to_str().unwrap(), boot.to_str().unwrap()],
        &format!("{}\n{}\n", lines[0], lines[2]),
    );
    assert!(unsealed.status.success(), "{unsealed:?}");
    for name in ["TPT_KEY_TOKEN", "TPT_KEY_AUDIT"] {
        assert_eq!(
            fs::read(plain.join(name)).expect("plain"),
            fs::read(boot.join(name)).expect("boot"),
            "{name} differs after unseal"
        );
    }

    let refused = run(
        &[
            "unseal",
            blob.to_str().unwrap(),
            dir.join("x").to_str().unwrap(),
        ],
        &format!("{}\n", lines[1]),
    );
    assert!(!refused.status.success(), "one share unsealed the blob");
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[cfg(unix)]
fn stand_in_key_service(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    // Reverses its input. Reversal is a bijection, so it stands in for wrap and unwrap.
    fs::write(path, "#!/bin/sh\nrev\n").expect("script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
}

#[cfg(unix)]
#[test]
fn wrapped_custody_round_trips_and_needs_the_program_to_unseal() {
    let dir = scratch("wrapped");
    let plain = dir.join("plain");
    let service = dir.join("service.sh");
    stand_in_key_service(&service);
    let generated = run(&["generate", plain.to_str().unwrap(), "TPT_KEY_TOKEN"], "");
    assert!(generated.status.success(), "{generated:?}");

    let blob = dir.join("keys.blob");
    let sealed = run(
        &[
            "seal",
            plain.to_str().unwrap(),
            blob.to_str().unwrap(),
            "--kms-wrap",
            service.to_str().unwrap(),
        ],
        "",
    );
    assert!(sealed.status.success(), "{sealed:?}");
    assert!(
        shares_from(&sealed).is_empty(),
        "wrapped custody printed shares"
    );

    let boot = dir.join("boot");
    let unsealed = run(
        &[
            "unseal",
            blob.to_str().unwrap(),
            boot.to_str().unwrap(),
            "--kms-unwrap",
            service.to_str().unwrap(),
        ],
        "",
    );
    assert!(unsealed.status.success(), "{unsealed:?}");
    assert_eq!(
        fs::read(plain.join("TPT_KEY_TOKEN")).expect("plain"),
        fs::read(boot.join("TPT_KEY_TOKEN")).expect("boot")
    );

    // Without the program, a wrapped blob does not unseal.
    let missing = run(
        &[
            "unseal",
            blob.to_str().unwrap(),
            dir.join("x").to_str().unwrap(),
        ],
        "",
    );
    assert!(!missing.status.success());
    fs::remove_dir_all(&dir).expect("cleanup");
}
