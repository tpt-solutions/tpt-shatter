// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use super::*;

const KEYS: [(&str, [u8; 32]); 2] = [("TPT_KEY_AUDIT", [0x11; 32]), ("TPT_KEY_TOKEN", [0x22; 32])];

fn pairs() -> Vec<(&'static str, [u8; 32])> {
    KEYS.to_vec()
}

fn check(recovered: &[KeyEntry]) {
    assert_eq!(recovered.len(), KEYS.len());
    for ((name, key), (want_name, want_key)) in recovered.iter().zip(KEYS.iter()) {
        assert_eq!(name, want_name);
        assert_eq!(&key[..], &want_key[..]);
    }
}

#[test]
fn shamir_any_two_shares_recover_the_keys() {
    let sealed = seal_shamir(&pairs()).expect("seal");
    assert_eq!(sealed.shares.len(), CUSTODIANS);
    assert_eq!(custody(&sealed.blob), Ok(Custody::Shamir));
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        let two = vec![sealed.shares[i].clone(), sealed.shares[j].clone()];
        check(&unseal_shamir(&sealed.blob, &two).expect("unseal"));
    }
}

#[test]
fn shamir_one_share_is_refused() {
    let sealed = seal_shamir(&pairs()).expect("seal");
    assert!(unseal_shamir(&sealed.blob, &sealed.shares[..1]).is_err());
    assert!(unseal_shamir(&sealed.blob, &[]).is_err());
}

#[test]
fn shamir_tampered_blob_is_refused() {
    let sealed = seal_shamir(&pairs()).expect("seal");
    let shares = &sealed.shares[..2];
    let mut flipped = sealed.blob.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(
        unseal_shamir(&flipped, shares).is_err(),
        "tampered ciphertext opened"
    );
}

#[test]
fn shares_from_different_seals_do_not_mix() {
    let first = seal_shamir(&pairs()).expect("first");
    let second = seal_shamir(&pairs()).expect("second");
    let mixed = vec![first.shares[0].clone(), second.shares[1].clone()];
    assert!(unseal_shamir(&first.blob, &mixed).is_err());
    assert!(unseal_shamir(&second.blob, &mixed).is_err());
}

#[test]
fn wrapped_round_trip_with_the_unwrapped_kek() {
    let kek = random_key();
    let wrapped = b"cloud-kms-ciphertext-bytes";
    let blob = seal_wrapped(&pairs(), &kek, wrapped).expect("seal");
    assert_eq!(custody(&blob), Ok(Custody::Wrapped));
    assert_eq!(wrapped_kek(&blob), Ok(Some(wrapped.to_vec())));
    check(&unseal_wrapped(&blob, &kek).expect("unseal"));
}

#[test]
fn wrapped_wrong_kek_is_refused() {
    let kek = random_key();
    let blob = seal_wrapped(&pairs(), &kek, b"w").expect("seal");
    let other = random_key();
    assert!(unseal_wrapped(&blob, &other).is_err());
}

#[test]
fn wrapped_header_is_authenticated() {
    let kek = random_key();
    let blob = seal_wrapped(&pairs(), &kek, b"wrapped-one").expect("seal");
    // Changing a byte of the stored wrapped KEK must fail the AEAD check.
    let mut altered = blob.clone();
    altered[4] ^= 0x01;
    assert!(
        unseal_wrapped(&altered, &kek).is_err(),
        "header changed without detection"
    );
}

#[test]
fn a_blob_cannot_be_opened_in_the_other_mode() {
    let kek = random_key();
    let wrapped_blob = seal_wrapped(&pairs(), &kek, b"w").expect("wrapped");
    let shamir = seal_shamir(&pairs()).expect("shamir");
    // Recovering the Shamir KEK must not open a wrapped blob, and the reverse.
    assert!(unseal_shamir(&wrapped_blob, &shamir.shares[..2]).is_err());
    assert!(unseal_wrapped(&shamir.blob, &kek).is_err());
}

#[test]
fn a_wrapped_blob_cannot_be_downgraded_to_shamir_mode() {
    let kek = random_key();
    let mut blob = seal_wrapped(&pairs(), &kek, b"w").expect("seal");
    blob[1] = MODE_SHAMIR;
    // A Shamir mode byte with a wrapped KEK present is an inconsistent header, so it is refused.
    assert!(custody(&blob).is_err(), "inconsistent header was accepted");
    assert!(unseal_wrapped(&blob, &kek).is_err());
}

#[test]
fn an_empty_or_oversized_wrap_is_refused() {
    let kek = random_key();
    assert!(seal_wrapped(&pairs(), &kek, &[]).is_err());
    assert!(seal_wrapped(&pairs(), &kek, &vec![0u8; MAX_WRAPPED + 1]).is_err());
}

#[test]
fn names_must_be_plain_and_unique() {
    assert!(seal_shamir(&[("../etc", [0; 32])]).is_err());
    assert!(seal_shamir(&[("", [0; 32])]).is_err());
    assert!(seal_shamir(&[("A", [0; 32]), ("A", [1; 32])]).is_err());
    assert!(valid_name("TPT_KEY_VAULT_A"));
    assert!(!valid_name("has space"));
}
