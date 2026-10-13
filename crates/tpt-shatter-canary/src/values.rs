// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Realistic-looking canary values.
//!
//! The schema records no type for a field, so the value shape comes from the field
//! name: card-like names get a Luhn-valid number, date-like names a date, and so on.
//! Any other name gets an opaque ID. Every value is derived from the canary key and
//! the field name, so only holders of the canary key can reproduce one.
//!
//! The shapes use test ranges where one exists: `.invalid` email domains (RFC 2606) and
//! the 555-01xx phone block. Card-like values are not in a test range, so they can
//! match a real card by chance. They are only stored in the vaults, and never leave them.

const FIRST_NAMES: [&str; 8] = [
    "Alex", "Jordan", "Morgan", "Casey", "Riley", "Sam", "Taylor", "Quinn",
];
const LAST_NAMES: [&str; 8] = [
    "Ashford",
    "Bennett",
    "Carver",
    "Dalton",
    "Ellison",
    "Fairbanks",
    "Garrow",
    "Holt",
];

/// The value for one field, shaped by the field name and seeded by `seed`.
#[must_use]
pub fn canary_value(field: &str, seed: &[u8; 32]) -> String {
    // Match whole name parts, so "company" does not read as "pan".
    let lowered = field.to_ascii_lowercase();
    let parts: Vec<&str> = lowered.split('_').collect();
    let has = |words: &[&str]| parts.iter().any(|p| words.contains(p));
    if has(&["card", "pan"]) {
        card_number(seed)
    } else if has(&["email"]) {
        format!(
            "{}.{}@example.invalid",
            word(&FIRST_NAMES, seed[0]),
            word(&LAST_NAMES, seed[1])
        )
        .to_ascii_lowercase()
    } else if has(&["phone"]) {
        format!("+1 555-01{:02}", seed[0] % 100)
    } else if has(&["year"]) {
        format!("{}", 1940 + u32::from(seed[0]) % 66)
    } else if has(&["birth", "dob", "date"]) {
        date(seed)
    } else if has(&["name"]) {
        format!(
            "{} {}",
            word(&FIRST_NAMES, seed[0]),
            word(&LAST_NAMES, seed[1])
        )
    } else {
        digits_and_letters(seed, 10)
    }
}

fn word(pool: &[&'static str], byte: u8) -> &'static str {
    pool[usize::from(byte) % pool.len()]
}

/// A 16-digit number with a valid Luhn check digit, starting with 4 (the Visa range).
fn card_number(seed: &[u8; 32]) -> String {
    let mut digits: Vec<u32> = vec![4];
    digits.extend(seed.iter().take(14).map(|b| u32::from(b % 10)));
    // Luhn: double every second digit from the right, starting with the digit
    // immediately left of the check digit. The check digit makes the total a multiple of 10.
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            if i % 2 == 0 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                *d
            }
        })
        .sum();
    digits.push((10 - sum % 10) % 10);
    digits.iter().map(u32::to_string).collect()
}

/// A date between 1940-01-01 and 2005-12-28, as `YYYY-MM-DD`. Every month has 28 days,
/// so the day is always valid.
fn date(seed: &[u8; 32]) -> String {
    let year = 1940 + u32::from(seed[0]) % 66;
    let month = 1 + u32::from(seed[1]) % 12;
    let day = 1 + u32::from(seed[2]) % 28;
    format!("{year:04}-{month:02}-{day:02}")
}

fn digits_and_letters(seed: &[u8; 32], len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    seed.iter()
        .take(len)
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x5B; 32];

    fn luhn_valid(number: &str) -> bool {
        let sum: u32 = number
            .chars()
            .rev()
            .enumerate()
            .map(|(i, c)| {
                let d = c.to_digit(10).expect("digit");
                if i % 2 == 1 {
                    let doubled = d * 2;
                    if doubled > 9 { doubled - 9 } else { doubled }
                } else {
                    d
                }
            })
            .sum();
        sum % 10 == 0
    }

    #[test]
    fn card_numbers_are_sixteen_digits_and_pass_luhn() {
        for byte in 0..=255u8 {
            let mut seed = SEED;
            seed[5] = byte;
            let value = canary_value("card_number", &seed);
            assert_eq!(value.len(), 16);
            assert!(value.starts_with('4'));
            assert!(luhn_valid(&value), "{value}");
        }
    }

    #[test]
    fn dates_and_years_are_in_range() {
        let value = canary_value("birth_date", &SEED);
        assert_eq!(value.len(), 10);
        let year: u32 = value[..4].parse().expect("year");
        assert!((1940..=2005).contains(&year));
        let year_only: u32 = canary_value("birth_year", &SEED).parse().expect("year");
        assert!((1940..=2005).contains(&year_only));
    }

    #[test]
    fn names_and_emails_look_like_people_and_use_test_domains() {
        let name = canary_value("full_name", &SEED);
        assert!(name.contains(' '));
        let email = canary_value("email", &SEED);
        assert!(email.ends_with("@example.invalid"));
        assert!(!email.contains(' '));
    }

    #[test]
    fn unknown_fields_get_an_opaque_id() {
        let id = canary_value("zz_field", &SEED);
        assert_eq!(id.len(), 10);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn values_are_deterministic_for_a_seed() {
        assert_eq!(canary_value("name", &SEED), canary_value("name", &SEED));
        assert_ne!(
            canary_value("name", &SEED),
            canary_value("name", &[0x11; 32])
        );
    }
}
