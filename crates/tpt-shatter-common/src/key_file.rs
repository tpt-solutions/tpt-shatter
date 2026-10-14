// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Reading 32-byte keys from files, with the permission checks the services rely on.

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::ShatterError;

/// Reads a 32-byte key from a file of 64 hex characters. On Unix, a file readable or writable
/// by group or others is refused. Errors never include the file's contents.
pub fn read_key_file(path: &Path) -> Result<[u8; 32], ShatterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|_| ShatterError::InvalidParameter)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(ShatterError::InvalidParameter);
        }
    }
    let text =
        Zeroizing::new(fs::read_to_string(path).map_err(|_| ShatterError::InvalidParameter)?);
    let hex = text.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(ShatterError::InvalidParameter);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| ShatterError::InvalidParameter)?;
    }
    Ok(out)
}
