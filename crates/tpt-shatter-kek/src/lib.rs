// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Seals a set of 32-byte keys under a key-encryption key (KEK). The KEK is protected in one
//! of two ways, and the blob records which one.
//!
//! - **Shamir custody** (on-prem): the KEK is split into [`CUSTODIANS`] shares, any
//!   [`THRESHOLD`] of which recover it. Two custodians must be present at every boot.
//! - **Wrapped custody** (cloud): the KEK is encrypted by an external key service, such as a
//!   cloud KMS, through an operator-supplied wrap program. The blob stores the wrapped KEK.
//!   Unsealing runs the matching unwrap program. The library does not talk to any cloud.
//!
//! In both modes the keys are encrypted with ChaCha20-Poly1305 under the KEK. The header,
//! including the custody mode and the wrapped KEK, is authenticated, so the mode cannot be
//! changed to a weaker one.
//!
//! This is a narrow tool, not a KMS. It has no access control or audit of its own, so the
//! custody procedure in `docs/RUNBOOK.md` is part of the security boundary. The Shamir
//! implementation is `blahaj`, a fork of `sharks` that fixes RUSTSEC-2024-0398. Neither it
//! nor this tool has been independently audited.

use std::fmt::Write as _;

use blahaj::{Share, Sharks};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngExt as _;
use tpt_shatter_common::ShatterError;
use zeroize::Zeroizing;

/// Shares needed to recover a Shamir-custody KEK.
pub const THRESHOLD: u8 = 2;
/// Shares issued in Shamir custody, one per custodian.
pub const CUSTODIANS: usize = 3;
/// Longest wrapped KEK the blob accepts, in bytes. A cloud KMS ciphertext is far shorter.
pub const MAX_WRAPPED: usize = 1024;
/// Format version. Changing the format bumps it.
const VERSION: u8 = 2;
const MODE_SHAMIR: u8 = 1;
const MODE_WRAPPED: u8 = 2;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const AAD_LABEL: &[u8] = b"tpt-shatter/kek/v2";
/// Longest key name, in bytes.
const MAX_NAME: usize = 64;

/// One key recovered by unseal: its name, and the 32 key bytes, zeroed on drop.
pub type KeyEntry = (String, Zeroizing<[u8; KEY_LEN]>);

/// How a blob's KEK is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// The KEK is recovered from [`THRESHOLD`] of the [`CUSTODIANS`] shares.
    Shamir,
    /// The KEK is recovered by unwrapping the stored wrapped KEK.
    Wrapped,
}

/// The output of [`seal_shamir`]: the encrypted blob, and one share per custodian.
pub struct Sealed {
    /// The encrypted keys. Not secret without the KEK, so it may be stored with the nodes.
    pub blob: Vec<u8>,
    /// One share per custodian. Each must go to a different person and be stored separately.
    pub shares: Vec<Vec<u8>>,
}

/// A fresh random 32-byte key.
#[must_use]
pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rng().fill(&mut key[..]);
    key
}

/// Whether `name` is an allowed key name: 1 to 64 ASCII letters, digits, or underscores.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Seals `keys` under a fresh KEK, and splits the KEK among [`CUSTODIANS`] custodians.
pub fn seal_shamir(keys: &[(&str, [u8; KEY_LEN])]) -> Result<Sealed, ShatterError> {
    let kek = random_key();
    let blob = encrypt(keys, &kek, MODE_SHAMIR, &[])?;
    let shares = Sharks(THRESHOLD)
        .dealer(&kek[..])
        .take(CUSTODIANS)
        .map(|share| Vec::from(&share))
        .collect();
    Ok(Sealed { blob, shares })
}

/// Seals `keys` under `kek`, recording `wrapped` as the external wrap of that KEK. The caller
/// has already produced `wrapped` by wrapping `kek` with the external key service.
pub fn seal_wrapped(
    keys: &[(&str, [u8; KEY_LEN])],
    kek: &[u8; KEY_LEN],
    wrapped: &[u8],
) -> Result<Vec<u8>, ShatterError> {
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED {
        return Err(ShatterError::InvalidParameter);
    }
    encrypt(keys, kek, MODE_WRAPPED, wrapped)
}

/// The custody mode of `blob`, from its header.
pub fn custody(blob: &[u8]) -> Result<Custody, ShatterError> {
    match parse_header(blob)?.mode {
        MODE_SHAMIR => Ok(Custody::Shamir),
        _ => Ok(Custody::Wrapped),
    }
}

/// The wrapped KEK stored in a wrapped-custody blob. `None` for Shamir custody.
pub fn wrapped_kek(blob: &[u8]) -> Result<Option<Vec<u8>>, ShatterError> {
    let header = parse_header(blob)?;
    Ok((header.mode == MODE_WRAPPED).then(|| header.wrapped.to_vec()))
}

/// Unseals a Shamir-custody blob with at least [`THRESHOLD`] shares.
///
/// Errors are fixed values. A wrong share, a tampered blob, and too few shares all fail the
/// same way, so the error says nothing about which one it was.
pub fn unseal_shamir(blob: &[u8], shares: &[Vec<u8>]) -> Result<Vec<KeyEntry>, ShatterError> {
    let refused = || ShatterError::InvalidParameter;
    if parse_header(blob)?.mode != MODE_SHAMIR {
        return Err(refused());
    }
    let parsed: Vec<Share> = shares
        .iter()
        .map(|s| Share::try_from(&s[..]))
        .collect::<Result<_, _>>()
        .map_err(|_| refused())?;
    let recovered = Zeroizing::new(Sharks(THRESHOLD).recover(&parsed).map_err(|_| refused())?);
    if recovered.len() != KEY_LEN {
        return Err(refused());
    }
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    kek.copy_from_slice(&recovered);
    decrypt(blob, &kek, MODE_SHAMIR)
}

/// Unseals a wrapped-custody blob with its KEK, already unwrapped by the external service.
pub fn unseal_wrapped(blob: &[u8], kek: &[u8; KEY_LEN]) -> Result<Vec<KeyEntry>, ShatterError> {
    if parse_header(blob)?.mode != MODE_WRAPPED {
        return Err(ShatterError::InvalidParameter);
    }
    decrypt(blob, kek, MODE_WRAPPED)
}

/// The fixed-length prefix of a blob, and the wrapped KEK that follows it.
struct Header<'a> {
    mode: u8,
    wrapped: &'a [u8],
    /// Everything before the nonce. It is the authenticated header.
    bytes: &'a [u8],
}

fn parse_header(blob: &[u8]) -> Result<Header<'_>, ShatterError> {
    let refused = || ShatterError::InvalidParameter;
    if blob.len() < 4 || blob[0] != VERSION {
        return Err(refused());
    }
    let mode = blob[1];
    if mode != MODE_SHAMIR && mode != MODE_WRAPPED {
        return Err(refused());
    }
    let wrapped_len = usize::from(u16::from_be_bytes([blob[2], blob[3]]));
    if wrapped_len > MAX_WRAPPED || blob.len() < 4 + wrapped_len + NONCE_LEN + TAG_LEN {
        return Err(refused());
    }
    // A Shamir blob carries no wrapped KEK, and a wrapped blob must carry one.
    if (mode == MODE_SHAMIR) != (wrapped_len == 0) {
        return Err(refused());
    }
    let end = 4 + wrapped_len;
    Ok(Header {
        mode,
        wrapped: &blob[4..end],
        bytes: &blob[..end],
    })
}

fn encrypt(
    keys: &[(&str, [u8; KEY_LEN])],
    kek: &[u8; KEY_LEN],
    mode: u8,
    wrapped: &[u8],
) -> Result<Vec<u8>, ShatterError> {
    let mut plaintext = Zeroizing::new(String::new());
    for (i, (name, key)) in keys.iter().enumerate() {
        if !valid_name(name) || keys[..i].iter().any(|(other, _)| other == name) {
            return Err(ShatterError::InvalidParameter);
        }
        plaintext.push_str(name);
        plaintext.push(' ');
        for byte in key {
            let _ = write!(plaintext, "{byte:02x}");
        }
        plaintext.push('\n');
    }

    let wrapped_len = u16::try_from(wrapped.len()).map_err(|_| ShatterError::InvalidParameter)?;
    let mut header = Vec::with_capacity(4 + wrapped.len());
    header.push(VERSION);
    header.push(mode);
    header.extend_from_slice(&wrapped_len.to_be_bytes());
    header.extend_from_slice(wrapped);

    let cipher = ChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| ShatterError::Internal)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce[..]);
    let aad = aad(&header);
    let ciphertext = cipher
        .encrypt(
            <&Nonce>::try_from(&nonce[..]).map_err(|_| ShatterError::Internal)?,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| ShatterError::Internal)?;

    let mut blob = header;
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt(blob: &[u8], kek: &[u8; KEY_LEN], mode: u8) -> Result<Vec<KeyEntry>, ShatterError> {
    let refused = || ShatterError::InvalidParameter;
    let header = parse_header(blob)?;
    if header.mode != mode {
        return Err(refused());
    }
    let nonce_at = header.bytes.len();
    let nonce = &blob[nonce_at..nonce_at + NONCE_LEN];
    let cipher = ChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| refused())?;
    let aad = aad(header.bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                <&Nonce>::try_from(nonce).map_err(|_| refused())?,
                Payload {
                    msg: &blob[nonce_at + NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| refused())?,
    );
    parse(&plaintext).ok_or_else(refused)
}

/// The associated data: the fixed label, then the header bytes, so any header change fails.
fn aad(header: &[u8]) -> Vec<u8> {
    let mut aad = AAD_LABEL.to_vec();
    aad.extend_from_slice(header);
    aad
}

fn parse(plaintext: &[u8]) -> Option<Vec<KeyEntry>> {
    let text = std::str::from_utf8(plaintext).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let (name, hex) = line.split_once(' ')?;
        if !valid_name(name) || hex.len() != KEY_LEN * 2 {
            return None;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        out.push((name.to_owned(), key));
    }
    Some(out)
}

#[cfg(test)]
mod tests;
