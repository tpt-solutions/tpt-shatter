// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use tpt_shatter_common::ShatterError;
use zeroize::Zeroizing;

/// Longest field name accepted when decoding, matching the schema limit.
const MAX_NAME_LEN: usize = 64;

/// Encodes `(name, value)` pairs as a fragment body.
///
/// Each entry is `u32 name_len | name | u32 value_len | value`, with big-endian lengths.
/// The output is zeroed on drop because it holds field values.
pub fn encode_fields<'a, I>(fields: I) -> Result<Zeroizing<Vec<u8>>, ShatterError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = Zeroizing::new(Vec::new());
    for (name, value) in fields {
        push_chunk(&mut out, name.as_bytes())?;
        push_chunk(&mut out, value.as_bytes())?;
    }
    Ok(out)
}

/// Decodes a fragment body into `(name, value)` pairs.
///
/// Malformed input, such as truncated lengths, invalid UTF-8, or an oversized name,
/// yields [`ShatterError::Reconstruction`]. Decoding never returns a partial result.
pub fn decode_fields(bytes: &[u8]) -> Result<Vec<(String, Zeroizing<String>)>, ShatterError> {
    let mut rest = bytes;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (name_bytes, after_name) = take_chunk(rest)?;
        let (value_bytes, after_value) = take_chunk(after_name)?;
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(ShatterError::Reconstruction);
        }
        // Using `str::from_utf8` on the slice avoids an unzeroed intermediate Vec.
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ShatterError::Reconstruction)?
            .to_owned();
        let value = std::str::from_utf8(value_bytes)
            .map_err(|_| ShatterError::Reconstruction)?
            .to_owned();
        out.push((name, Zeroizing::new(value)));
        rest = after_value;
    }
    Ok(out)
}

fn push_chunk(out: &mut Vec<u8>, chunk: &[u8]) -> Result<(), ShatterError> {
    let len = u32::try_from(chunk.len()).map_err(|_| ShatterError::InvalidParameter)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(chunk);
    Ok(())
}

fn take_chunk(input: &[u8]) -> Result<(&[u8], &[u8]), ShatterError> {
    let (len_bytes, rest) = input
        .split_first_chunk::<4>()
        .ok_or(ShatterError::Reconstruction)?;
    let len = u32::from_be_bytes(*len_bytes) as usize;
    if len > rest.len() {
        return Err(ShatterError::Reconstruction);
    }
    Ok(rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fields() {
        let body = encode_fields([("name", "A. Example"), ("zip", "12345")]).expect("encode");
        let decoded = decode_fields(&body).expect("decode");
        let pairs: Vec<(&str, &str)> = decoded
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(pairs, [("name", "A. Example"), ("zip", "12345")]);
    }

    #[test]
    fn empty_body_decodes_to_no_fields() {
        assert!(decode_fields(&[]).expect("decode").is_empty());
    }

    #[test]
    fn rejects_truncated_input() {
        let body = encode_fields([("name", "value")]).expect("encode");
        for cut in 1..body.len() {
            assert_eq!(
                decode_fields(&body[..cut]).err(),
                Some(ShatterError::Reconstruction),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8_and_empty_names() {
        // name_len=2, name=0xFF 0xFE, value_len=0
        let bad_utf8 = [0, 0, 0, 2, 0xFF, 0xFE, 0, 0, 0, 0];
        assert_eq!(
            decode_fields(&bad_utf8).err(),
            Some(ShatterError::Reconstruction)
        );
        // name_len=0, value_len=0
        let empty_name = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_fields(&empty_name).err(),
            Some(ShatterError::Reconstruction)
        );
    }

    #[test]
    fn rejects_oversized_length_prefix() {
        let huge = [0xFF, 0xFF, 0xFF, 0xFF, b'x'];
        assert_eq!(
            decode_fields(&huge).err(),
            Some(ShatterError::Reconstruction)
        );
    }
}
