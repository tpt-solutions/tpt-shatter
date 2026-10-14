// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use tpt_shatter_common::{FragmentId, ShardKey, ShatterError, VaultId};

pub use tpt_shatter_common::keyed_digest;

/// Derives the FragmentId for `shard` in `vault`.
///
/// The result is `HMAC-SHA256(derivation_key, vault_domain_tag || 0x00 || shard_key)`.
/// The per-vault domain tag gives each vault a different ID for the same shard, so
/// vault contents cannot be linked to each other without the key. No mapping table is
/// needed, because the assembler re-derives the same IDs.
pub fn derive_fragment_id(
    derivation_key: &[u8],
    shard: &ShardKey,
    vault: VaultId,
) -> Result<FragmentId, ShatterError> {
    let digest = keyed_digest(
        derivation_key,
        vault.domain_tag().as_bytes(),
        shard.as_bytes(),
    )?;
    Ok(FragmentId::from_bytes(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_shatter_common::SHARD_KEY_LEN;

    const KEY: &[u8] = &[0x42; 32];

    #[test]
    fn same_inputs_give_same_id() {
        let shard = ShardKey::from_bytes([1; SHARD_KEY_LEN]);
        let a = derive_fragment_id(KEY, &shard, VaultId::A).expect("a");
        let b = derive_fragment_id(KEY, &shard, VaultId::A).expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn vaults_get_distinct_ids_for_the_same_shard() {
        let shard = ShardKey::from_bytes([1; SHARD_KEY_LEN]);
        let ids: Vec<_> = VaultId::ALL
            .iter()
            .map(|v| derive_fragment_id(KEY, &shard, *v).expect("id"))
            .collect();
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    }

    #[test]
    fn different_keys_or_shards_change_the_id() {
        let shard = ShardKey::from_bytes([1; SHARD_KEY_LEN]);
        let other_shard = ShardKey::from_bytes([2; SHARD_KEY_LEN]);
        let base = derive_fragment_id(KEY, &shard, VaultId::B).expect("base");
        let other_key = derive_fragment_id(&[0x43; 32], &shard, VaultId::B).expect("key");
        let shifted = derive_fragment_id(KEY, &other_shard, VaultId::B).expect("shard");
        assert!(base != other_key);
        assert!(base != shifted);
    }

    #[test]
    fn keyed_digest_separates_domain_from_data() {
        let x = keyed_digest(KEY, b"ab", b"c").expect("x");
        let y = keyed_digest(KEY, b"a", b"bc").expect("y");
        assert_ne!(x, y);
    }
}
