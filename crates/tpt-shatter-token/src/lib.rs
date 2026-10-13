// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Stateless capability tokens for tpt-shatter.
//!
//! A token is `base64url(payload || tag)`. The payload holds a 256-bit random ID,
//! the signing-key version, scopes, the issue and expiry times, and the bound
//! shard key. The tag is HMAC-SHA256 over the payload. Tokens are validated
//! with no session store.
//!
//! # Design decisions
//!
//! - **TTL:** 60 seconds by default, capped at 300. Expiry is strict. Only
//!   issue-time skew is tolerated (see [`CLOCK_SKEW_SECS`]).
//! - **Replay:** tokens are not single-use. A stolen token is replayable until it
//!   expires, at most 60 seconds, and only against its bound shard and scopes. A
//!   nonce store would make validation stateful, which this design rules out.
//!   Rotating the key invalidates every outstanding token immediately.
//! - **Shard binding:** the raw shard key travels inside the token, because the
//!   gateway must route by it. Whoever holds a token therefore holds the routing
//!   key for 60 seconds. Vault access still requires assembler credentials.
//! - **Key provisioning:** this crate takes key bytes from the caller. How keys
//!   are provisioned and rotated is Phase 11 (Gap 5).

use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tpt_shatter_common::{
    CALLER_TAG_LEN, CapabilityToken, DEFAULT_TOKEN_TTL_SECS, SHARD_KEY_LEN, Scope, Scopes,
    ShardKey, ShatterError,
};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Token format version written into every token.
pub const TOKEN_VERSION: u8 = 2;

/// Longest permitted token lifetime, in seconds.
pub const MAX_TTL_SECS: u64 = 300;

/// How far in the future a token's issue time may be, to absorb clock skew.
pub const CLOCK_SKEW_SECS: u64 = 5;

const ID_LEN: usize = 32;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 32;
// version | key_version | id | scopes | issued_at | expires_at | caller | shard_key
const OFF_ID: usize = 5;
const OFF_SCOPES: usize = OFF_ID + ID_LEN;
const OFF_ISSUED: usize = OFF_SCOPES + 4;
const OFF_EXPIRES: usize = OFF_ISSUED + 8;
const OFF_CALLER: usize = OFF_EXPIRES + 8;
const OFF_SHARD: usize = OFF_CALLER + CALLER_TAG_LEN;
const PAYLOAD_LEN: usize = OFF_SHARD + SHARD_KEY_LEN;

/// Caller tag for a token issued without one. The node always issues with a caller.
pub const UNATTRIBUTED: [u8; CALLER_TAG_LEN] = [0; CALLER_TAG_LEN];
const TOKEN_LEN: usize = PAYLOAD_LEN + TAG_LEN;

/// Issues and verifies capability tokens under one signing key.
///
/// Rotating the key with [`Signer::rotate`] invalidates every token issued under
/// the previous version at once.
pub struct Signer {
    key_version: u32,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl Signer {
    /// Creates a signer for `key_version` with the given 256-bit key.
    #[must_use]
    pub fn new(key_version: u32, key: [u8; KEY_LEN]) -> Self {
        Self {
            key_version,
            key: Zeroizing::new(key),
        }
    }

    /// Replaces the signing key. Every token issued under the old key stops verifying.
    pub fn rotate(&mut self, key_version: u32, key: [u8; KEY_LEN]) {
        self.key_version = key_version;
        self.key = Zeroizing::new(key);
    }

    /// The active key version.
    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Issues a token with the default TTL. The returned string is a bearer secret.
    pub fn issue(
        &self,
        shard_key: &ShardKey,
        scopes: Scopes,
        now: u64,
    ) -> Result<Zeroizing<String>, ShatterError> {
        self.issue_with_ttl(shard_key, scopes, now, DEFAULT_TOKEN_TTL_SECS)
    }

    /// Issues a token with an explicit TTL in `1..=MAX_TTL_SECS`, with no caller tag.
    pub fn issue_with_ttl(
        &self,
        shard_key: &ShardKey,
        scopes: Scopes,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Zeroizing<String>, ShatterError> {
        self.issue_for(&UNATTRIBUTED, shard_key, scopes, now, ttl_secs)
    }

    /// Issues a token tagged with `caller`, with an explicit TTL in `1..=MAX_TTL_SECS`.
    /// The tag is covered by the signature, so the gateway can attribute each use.
    pub fn issue_for(
        &self,
        caller: &[u8; CALLER_TAG_LEN],
        shard_key: &ShardKey,
        scopes: Scopes,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Zeroizing<String>, ShatterError> {
        if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
            return Err(ShatterError::InvalidParameter);
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN + TAG_LEN));
        payload.push(TOKEN_VERSION);
        payload.extend_from_slice(&self.key_version.to_be_bytes());
        payload.extend_from_slice(&random_id());
        payload.extend_from_slice(&scopes.bits().to_be_bytes());
        payload.extend_from_slice(&now.to_be_bytes());
        payload.extend_from_slice(&now.saturating_add(ttl_secs).to_be_bytes());
        payload.extend_from_slice(caller);
        payload.extend_from_slice(shard_key.as_bytes());
        let tag = self.tag(&payload)?;
        payload.extend_from_slice(&tag);
        Ok(Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(&payload[..])))
    }

    /// Verifies a token string at time `now` (Unix seconds) and returns its claims.
    ///
    /// Malformed, mis-versioned, wrongly keyed, or forged input yields
    /// [`ShatterError::InvalidToken`]. Expired input yields [`ShatterError::TokenExpired`].
    pub fn verify(&self, token: &str, now: u64) -> Result<CapabilityToken, ShatterError> {
        let raw = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| ShatterError::InvalidToken)?,
        );
        if raw.len() != TOKEN_LEN || raw[0] != TOKEN_VERSION {
            return Err(ShatterError::InvalidToken);
        }
        let (payload, tag) = raw.split_at(PAYLOAD_LEN);

        let key_version = read_u32(&payload[1..5]);
        if key_version != self.key_version {
            return Err(ShatterError::InvalidToken);
        }
        let mut mac =
            HmacSha256::new_from_slice(&self.key[..]).map_err(|_| ShatterError::Internal)?;
        mac.update(payload);
        mac.verify_slice(tag)
            .map_err(|_| ShatterError::InvalidToken)?;

        // The tag is authentic, so the fields below are trusted. Still validate them.
        let id = to_array::<ID_LEN>(&payload[OFF_ID..OFF_SCOPES]);
        let scopes = Scopes::from_bits(read_u32(&payload[OFF_SCOPES..OFF_ISSUED]));
        let issued_at = read_u64(&payload[OFF_ISSUED..OFF_EXPIRES]);
        let expires_at = read_u64(&payload[OFF_EXPIRES..OFF_CALLER]);
        let caller = to_array::<CALLER_TAG_LEN>(&payload[OFF_CALLER..OFF_SHARD]);
        let shard = to_array::<SHARD_KEY_LEN>(&payload[OFF_SHARD..]);

        let lifetime = expires_at
            .checked_sub(issued_at)
            .filter(|l| *l > 0 && *l <= MAX_TTL_SECS)
            .ok_or(ShatterError::InvalidToken)?;
        if issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(ShatterError::InvalidToken);
        }
        if now >= expires_at {
            return Err(ShatterError::TokenExpired);
        }
        Ok(CapabilityToken::new(
            id,
            scopes,
            issued_at,
            lifetime,
            caller,
            ShardKey::from_bytes(shard),
        ))
    }

    /// Verifies a token and checks that it is bound to `shard_key`.
    ///
    /// A token for a different shard yields [`ShatterError::Unauthorized`].
    pub fn verify_for_shard(
        &self,
        token: &str,
        shard_key: &ShardKey,
        now: u64,
    ) -> Result<CapabilityToken, ShatterError> {
        let claims = self.verify(token, now)?;
        if !ct_eq(claims.shard_key().as_bytes(), shard_key.as_bytes()) {
            return Err(ShatterError::Unauthorized);
        }
        Ok(claims)
    }

    /// Verifies a token, checks the shard binding, and checks that `scope` is granted.
    pub fn authorize(
        &self,
        token: &str,
        shard_key: &ShardKey,
        scope: Scope,
        now: u64,
    ) -> Result<CapabilityToken, ShatterError> {
        let claims = self.verify_for_shard(token, shard_key, now)?;
        claims.check_scope(scope)?;
        Ok(claims)
    }

    fn tag(&self, payload: &[u8]) -> Result<[u8; TAG_LEN], ShatterError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key[..]).map_err(|_| ShatterError::Internal)?;
        mac.update(payload);
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    }
}

/// 256 bits of CSPRNG output from the thread-local generator.
fn random_id() -> [u8; ID_LEN] {
    let mut id = [0u8; ID_LEN];
    for chunk in id.chunks_exact_mut(8) {
        chunk.copy_from_slice(&rand::random::<u64>().to_be_bytes());
    }
    id
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(to_array::<4>(b))
}

fn read_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(to_array::<8>(b))
}

fn to_array<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(b);
    out
}

/// Constant-time comparison of two equal-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    a.len() == b.len() && diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: u64 = 1_000_000;

    fn signer() -> Signer {
        Signer::new(1, [0x11; KEY_LEN])
    }

    fn shard(byte: u8) -> ShardKey {
        ShardKey::from_bytes([byte; SHARD_KEY_LEN])
    }

    fn read_scope() -> Scopes {
        Scopes::from_scopes(&[Scope::Read])
    }

    #[test]
    fn the_caller_tag_round_trips_and_is_covered_by_the_signature() {
        let s = signer();
        let caller = [0xC4; CALLER_TAG_LEN];
        let tok = s
            .issue_for(
                &caller,
                &shard(7),
                read_scope(),
                NOW,
                DEFAULT_TOKEN_TTL_SECS,
            )
            .expect("issue");
        let claims = s.verify(&tok, NOW + 1).expect("verify");
        assert_eq!(claims.caller(), &caller);
        assert_eq!(claims.shard_key().as_bytes(), &[7; SHARD_KEY_LEN]);

        // Change one byte of the tag, then re-encode the token: the tag no longer verifies.
        let mut raw = BASE64_URL_SAFE_NO_PAD.decode(&tok).expect("decode");
        raw[OFF_CALLER] ^= 0x01;
        let forged = BASE64_URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(
            s.verify(&forged, NOW + 1).err(),
            Some(ShatterError::InvalidToken)
        );
    }

    #[test]
    fn tokens_issued_without_a_caller_carry_the_unattributed_tag() {
        let s = signer();
        let tok = s.issue(&shard(7), read_scope(), NOW).expect("issue");
        let claims = s.verify(&tok, NOW + 1).expect("verify");
        assert_eq!(claims.caller(), &UNATTRIBUTED);
    }

    #[test]
    fn issues_and_verifies_round_trip() {
        let s = signer();
        let tok = s.issue(&shard(7), read_scope(), NOW).expect("issue");
        let claims = s.verify(&tok, NOW + 1).expect("verify");
        assert_eq!(claims.expires_at(), NOW + DEFAULT_TOKEN_TTL_SECS);
        assert!(claims.check_scope(Scope::Read).is_ok());
        assert_eq!(claims.shard_key().as_bytes(), &[7; SHARD_KEY_LEN]);
    }

    #[test]
    fn ids_are_unique_and_long() {
        let s = signer();
        let a = s
            .verify(&s.issue(&shard(1), read_scope(), NOW).expect("a"), NOW)
            .expect("a");
        let b = s
            .verify(&s.issue(&shard(1), read_scope(), NOW).expect("b"), NOW)
            .expect("b");
        assert_eq!(a.id().len(), 32);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn expires_after_ttl_and_not_before() {
        let s = signer();
        let tok = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        assert!(s.verify(&tok, NOW + DEFAULT_TOKEN_TTL_SECS - 1).is_ok());
        assert_eq!(
            s.verify(&tok, NOW + DEFAULT_TOKEN_TTL_SECS).err(),
            Some(ShatterError::TokenExpired)
        );
    }

    #[test]
    fn tolerates_small_clock_skew_only() {
        let s = signer();
        let tok = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        assert!(s.verify(&tok, NOW - CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            s.verify(&tok, NOW - CLOCK_SKEW_SECS - 1).err(),
            Some(ShatterError::InvalidToken)
        );
    }

    #[test]
    fn rejects_tampered_tokens() {
        let s = signer();
        let tok = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        let mut raw = BASE64_URL_SAFE_NO_PAD.decode(tok.as_str()).expect("b64");
        // Flip one bit in the scopes field (after version + key version + id).
        raw[1 + 4 + ID_LEN + 3] ^= 0x02;
        let forged = BASE64_URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(
            s.verify(&forged, NOW).err(),
            Some(ShatterError::InvalidToken)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let tok = signer().issue(&shard(1), read_scope(), NOW).expect("issue");
        let other = Signer::new(1, [0x22; KEY_LEN]);
        assert_eq!(
            other.verify(&tok, NOW).err(),
            Some(ShatterError::InvalidToken)
        );
    }

    #[test]
    fn rotation_invalidates_outstanding_tokens() {
        let mut s = signer();
        let tok = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        assert!(s.verify(&tok, NOW).is_ok());
        s.rotate(2, [0x33; KEY_LEN]);
        assert_eq!(s.key_version(), 2);
        assert_eq!(s.verify(&tok, NOW).err(), Some(ShatterError::InvalidToken));
        let fresh = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        assert!(s.verify(&fresh, NOW).is_ok());
    }

    #[test]
    fn rejects_token_for_another_shard() {
        let s = signer();
        let tok = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        assert!(s.verify_for_shard(&tok, &shard(1), NOW).is_ok());
        assert_eq!(
            s.verify_for_shard(&tok, &shard(2), NOW).err(),
            Some(ShatterError::Unauthorized)
        );
    }

    #[test]
    fn authorize_checks_scope() {
        let s = signer();
        let tok = s.issue(&shard(1), read_scope(), NOW).expect("issue");
        assert!(s.authorize(&tok, &shard(1), Scope::Read, NOW).is_ok());
        assert_eq!(
            s.authorize(&tok, &shard(1), Scope::Delete, NOW).err(),
            Some(ShatterError::Unauthorized)
        );
    }

    #[test]
    fn rejects_bad_ttl() {
        let s = signer();
        assert_eq!(
            s.issue_with_ttl(&shard(1), read_scope(), NOW, 0).err(),
            Some(ShatterError::InvalidParameter)
        );
        assert_eq!(
            s.issue_with_ttl(&shard(1), read_scope(), NOW, MAX_TTL_SECS + 1)
                .err(),
            Some(ShatterError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        let s = signer();
        let long = "A".repeat(TOKEN_LEN * 2);
        for bad in ["", "!!!", "AAAA", long.as_str()] {
            assert_eq!(s.verify(bad, NOW).err(), Some(ShatterError::InvalidToken));
        }
    }

    #[test]
    fn debug_never_shows_the_shard_key() {
        let s = signer();
        let tok = s.issue(&shard(0xAB), read_scope(), NOW).expect("issue");
        let claims = s.verify(&tok, NOW).expect("verify");
        let shown = format!("{claims:?}");
        assert!(shown.contains("<redacted>"));
        // "Capability" contains "ab", so check for a run of the key's hex digits instead.
        assert!(!shown.contains("abababab"));
    }

    proptest! {
        // Stand-in for fuzzing: arbitrary input must never panic and must never verify.
        #[test]
        fn arbitrary_input_never_verifies(input in ".{0,400}") {
            let s = signer();
            prop_assert!(s.verify(&input, NOW).is_err());
        }

        #[test]
        fn arbitrary_bytes_never_verify(raw in proptest::collection::vec(any::<u8>(), 0..300)) {
            let s = signer();
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(&raw);
            prop_assert!(s.verify(&encoded, NOW).is_err());
        }
    }
}
