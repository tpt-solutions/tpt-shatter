// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `tpt-shatter-kek`: seals and unseals a node's keys under a key-encryption key.
//!
//! - `generate <dir> <name>...`: writes fresh random keys, one file each, mode 0400.
//! - `seal <dir> <blob>`: Shamir custody. Seals every key file in `dir` and prints three
//!   custodian shares, once. Delete `dir` afterwards.
//! - `seal <dir> <blob> --kms-wrap <program>`: cloud custody. The program receives the KEK as
//!   hex on stdin and prints the wrapped KEK as hex on stdout. The wrapped KEK is stored in
//!   the blob.
//! - `unseal <blob> <outdir>`: Shamir custody. Reads two shares from stdin, one per line.
//! - `unseal <blob> <outdir> --kms-unwrap <program>`: cloud custody. The program receives the
//!   wrapped KEK as hex on stdin and prints the KEK as hex on stdout.
//!
//! Programs run without a shell and are named only on the command line. The blob cannot
//! name a program. Point `outdir` at a tmpfs, and set the node's `TPT_KEYS_DIR` to it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use tpt_shatter_kek::{
    CUSTODIANS, Custody, THRESHOLD, custody, random_key, seal_shamir, seal_wrapped, unseal_shamir,
    unseal_wrapped, valid_name, wrapped_kek,
};

const USAGE: &str = "usage:
  tpt-shatter-kek generate <dir> <name>...
  tpt-shatter-kek seal <dir> <blob> [--kms-wrap <program>]
  tpt-shatter-kek unseal <blob> <outdir> [--kms-unwrap <program>]
  (Shamir custody reads two shares from stdin, one per line)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tpt-shatter-kek: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("generate") if args.len() >= 3 => generate(Path::new(&args[1]), &args[2..]),
        Some("seal") => {
            let (positional, flags) = split_flags(&args[1..], "--kms-wrap")?;
            match positional.as_slice() {
                [dir, blob] => seal_dir(Path::new(dir), Path::new(blob), flags.as_deref()),
                _ => Err(USAGE.to_owned()),
            }
        }
        Some("unseal") => {
            let (positional, flags) = split_flags(&args[1..], "--kms-unwrap")?;
            match positional.as_slice() {
                [blob, out] => unseal_to(Path::new(blob), Path::new(out), flags.as_deref()),
                _ => Err(USAGE.to_owned()),
            }
        }
        _ => Err(USAGE.to_owned()),
    }
}

/// Splits `args` into positional arguments and the value of `flag`, if given once.
fn split_flags(args: &[String], flag: &str) -> Result<(Vec<String>, Option<PathBuf>), String> {
    let mut positional = Vec::new();
    let mut program = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            let value = iter
                .next()
                .ok_or_else(|| format!("{flag} needs a program path"))?;
            if program.replace(PathBuf::from(value)).is_some() {
                return Err(format!("{flag} given twice"));
            }
        } else if arg.starts_with("--") {
            return Err(format!("unknown option {arg}"));
        } else {
            positional.push(arg.clone());
        }
    }
    Ok((positional, program))
}

fn generate(dir: &Path, names: &[String]) -> Result<(), String> {
    for name in names {
        if !valid_name(name) {
            return Err(format!("invalid key name {name:?}"));
        }
    }
    create_private_dir(dir)?;
    for name in names {
        let key = random_key();
        let mut file = create_secret_file(&dir.join(name))?;
        writeln!(file, "{}", hex(&key[..])).map_err(|_| "write failed".to_owned())?;
    }
    eprintln!("generated {} keys in {}", names.len(), dir.display());
    Ok(())
}

/// Reads every key file in `dir`. The names are the file names, and the files must be private.
fn read_keys(dir: &Path) -> Result<(Vec<String>, Vec<[u8; 32]>), String> {
    let mut names = Vec::new();
    let mut keys = Vec::new();
    for entry in fs::read_dir(dir).map_err(|_| "cannot read key directory".to_owned())? {
        let entry = entry.map_err(|_| "cannot read key directory".to_owned())?;
        if !entry
            .file_type()
            .map_err(|_| "cannot stat key file".to_owned())?
            .is_file()
        {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "key file name is not UTF-8".to_owned())?;
        if !valid_name(&name) {
            return Err(format!("key file name {name:?} is not allowed"));
        }
        keys.push(read_key_file(&entry.path())?);
        names.push(name);
    }
    if keys.is_empty() {
        return Err("no key files in the directory".to_owned());
    }
    Ok((names, keys))
}

fn seal_dir(dir: &Path, blob_path: &Path, wrap: Option<&Path>) -> Result<(), String> {
    let (names, keys) = read_keys(dir)?;
    let pairs: Vec<(&str, [u8; 32])> = names
        .iter()
        .zip(keys.iter())
        .map(|(n, k)| (n.as_str(), *k))
        .collect();

    let mut blob_file = create_secret_file(blob_path)?;
    match wrap {
        Some(program) => {
            // Cloud custody: the KEK is wrapped by the external program, and only the wrapped
            // form is stored.
            let kek = random_key();
            let wrapped = run_program(program, &hex(&kek[..]))?;
            let wrapped = parse_hex(&wrapped).ok_or_else(|| "wrap output is not hex".to_owned())?;
            let blob =
                seal_wrapped(&pairs, &kek, &wrapped).map_err(|_| "seal failed".to_owned())?;
            blob_file
                .write_all(&blob)
                .map_err(|_| "write failed".to_owned())?;
            eprintln!(
                "sealed {} keys into {} with a wrapped KEK. Delete {} once the blob is written.",
                pairs.len(),
                blob_path.display(),
                dir.display()
            );
        }
        None => {
            // Shamir custody: the KEK is split among the custodians.
            let sealed = seal_shamir(&pairs).map_err(|_| "seal failed".to_owned())?;
            blob_file
                .write_all(&sealed.blob)
                .map_err(|_| "write failed".to_owned())?;
            eprintln!(
                "sealed {} keys into {}. Give each share below to a different custodian. {} of {} are needed.",
                pairs.len(),
                blob_path.display(),
                THRESHOLD,
                CUSTODIANS
            );
            eprintln!("Delete {} once the shares are stored.", dir.display());
            for (i, share) in sealed.shares.iter().enumerate() {
                println!("custodian {}: {}", i + 1, hex(share));
            }
        }
    }
    Ok(())
}

fn unseal_to(blob_path: &Path, out_dir: &Path, unwrap: Option<&Path>) -> Result<(), String> {
    let blob = fs::read(blob_path).map_err(|_| "cannot read blob".to_owned())?;
    let keys = match custody(&blob).map_err(|_| "blob is not a valid key blob".to_owned())? {
        Custody::Shamir => {
            if unwrap.is_some() {
                return Err("this blob uses Shamir custody; drop --kms-unwrap".to_owned());
            }
            let shares = read_shares()?;
            unseal_shamir(&blob, &shares).map_err(|_| "unseal refused".to_owned())?
        }
        Custody::Wrapped => {
            let program = unwrap
                .ok_or_else(|| "this blob uses wrapped custody; pass --kms-unwrap".to_owned())?;
            let wrapped = wrapped_kek(&blob)
                .map_err(|_| "blob is not a valid key blob".to_owned())?
                .ok_or_else(|| "blob has no wrapped KEK".to_owned())?;
            let kek_hex = run_program(program, &hex(&wrapped))?;
            let kek = parse_hex(&kek_hex).ok_or_else(|| "unwrap output is not hex".to_owned())?;
            let kek = <[u8; 32]>::try_from(kek.as_slice())
                .map_err(|_| "unwrap output is not 32 bytes".to_owned())?;
            unseal_wrapped(&blob, &kek).map_err(|_| "unseal refused".to_owned())?
        }
    };

    create_private_dir(out_dir)?;
    for (name, key) in &keys {
        let mut file = create_secret_file(&out_dir.join(name))?;
        writeln!(file, "{}", hex(&key[..])).map_err(|_| "write failed".to_owned())?;
    }
    eprintln!("unsealed {} keys into {}", keys.len(), out_dir.display());
    Ok(())
}

/// Reads custodian shares from stdin: one per line, bare hex or the `custodian N: hex` form.
fn read_shares() -> Result<Vec<Vec<u8>>, String> {
    let mut shares = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|_| "cannot read shares".to_owned())?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let hex_part = line.rsplit(' ').next().unwrap_or(line);
        shares.push(parse_hex(hex_part).ok_or_else(|| "a share is not hex".to_owned())?);
    }
    if shares.len() < THRESHOLD as usize {
        return Err(format!(
            "{} shares given, {} are needed",
            shares.len(),
            THRESHOLD
        ));
    }
    Ok(shares)
}

/// Runs a key-service program with `input` on stdin, and returns its trimmed stdout. The
/// program is run directly, with no shell. Its stderr is shown to the operator.
fn run_program(program: &Path, input: &str) -> Result<String, String> {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "cannot start the key-service program".to_owned())?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "cannot write to the key-service program".to_owned())?;
        stdin
            .write_all(input.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|_| "the key-service program did not read its input".to_owned())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "the key-service program did not finish".to_owned())?;
    if !output.status.success() {
        return Err("the key-service program failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "the key-service program printed non-UTF-8 output".to_owned())
}

/// Reads a key file of 64 hex characters. On Unix, a file readable by group or others is
/// refused, so a plaintext key is never sealed from a shared-readable file.
fn read_key_file(path: &Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|_| "cannot stat key file".to_owned())?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err("a key file is readable by group or others".to_owned());
        }
    }
    let text = fs::read_to_string(path).map_err(|_| "cannot read key file".to_owned())?;
    let bytes = parse_hex(text.trim()).ok_or_else(|| "a key file is not hex".to_owned())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "a key file is not 32 bytes".to_owned())
}

fn create_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|_| "cannot create directory".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot restrict directory".to_owned())?;
    }
    Ok(())
}

/// Creates a new file that is never overwritten, with mode 0400 on Unix.
fn create_secret_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    options
        .open(path)
        .map_err(|_| format!("cannot create {} (it may already exist)", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn parse_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}
