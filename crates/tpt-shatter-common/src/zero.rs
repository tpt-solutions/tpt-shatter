// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use zeroize::Zeroize;

/// Overwrites sensitive data with zeros in a way the compiler cannot elide.
///
/// Implemented for every type that implements [`zeroize::Zeroize`], such as
/// byte arrays, `Vec<u8>`, and `String`.
pub trait SecureZero {
    /// Zeroes the value in place.
    fn secure_zero(&mut self);
}

impl<T: Zeroize + ?Sized> SecureZero for T {
    fn secure_zero(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroes_array_in_place() {
        let mut buf = [0xFFu8; 16];
        buf.secure_zero();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn zeroes_string_contents() {
        let mut s = String::from("sensitive");
        s.secure_zero();
        assert!(s.is_empty());
    }
}
