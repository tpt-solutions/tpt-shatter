// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Keyed digests for audit fields and derived identifiers.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::ShatterError;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 over `domain || 0x00 || data`, keyed by `key`.
///
/// The NUL separator keeps the domain and data unambiguous. Domain strings come
/// from code, not from input, so the separator is sufficient.
pub fn keyed_digest(key: &[u8], domain: &[u8], data: &[u8]) -> Result<[u8; 32], ShatterError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ShatterError::InvalidParameter)?;
    mac.update(domain);
    mac.update(&[0u8]);
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}
