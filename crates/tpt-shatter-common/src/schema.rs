// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::ShatterError;
use crate::vault::VaultId;

/// A versioned mapping from record field names to the vault that stores them.
///
/// Every field maps to exactly one vault. Which fields belong to which vault is
/// a Phase 0 decision, so this type validates structure only and does not
/// define a production schema.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawSchema")]
pub struct ShatterSchema {
    version: u32,
    mapping: BTreeMap<String, VaultId>,
}

/// On-disk form of a schema. Validated by [`ShatterSchema::new`] on conversion.
#[derive(Deserialize)]
struct RawSchema {
    version: u32,
    fields: BTreeMap<String, char>,
}

impl TryFrom<RawSchema> for ShatterSchema {
    type Error = ShatterError;

    fn try_from(raw: RawSchema) -> Result<Self, Self::Error> {
        let fields = raw
            .fields
            .into_iter()
            .map(|(name, label)| VaultId::from_label(label).map(|vault| (name, vault)))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(raw.version, fields)
    }
}

impl ShatterSchema {
    /// Builds a schema. Rejects version 0, an empty schema, malformed field
    /// names, and duplicate field names.
    pub fn new<I, S>(version: u32, fields: I) -> Result<Self, ShatterError>
    where
        I: IntoIterator<Item = (S, VaultId)>,
        S: Into<String>,
    {
        if version == 0 {
            return Err(ShatterError::InvalidSchema);
        }
        let mut mapping = BTreeMap::new();
        for (name, vault) in fields {
            let name = name.into();
            if !is_valid_field_name(&name) || mapping.insert(name, vault).is_some() {
                return Err(ShatterError::InvalidSchema);
            }
        }
        if mapping.is_empty() {
            return Err(ShatterError::InvalidSchema);
        }
        Ok(Self { version, mapping })
    }

    /// Schema version, stored alongside fragments so migrations can detect it.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The vault that stores `field`, if the field is part of the schema.
    #[must_use]
    pub fn vault_for(&self, field: &str) -> Option<VaultId> {
        self.mapping.get(field).copied()
    }

    /// Field names stored in `vault`, in sorted order.
    pub fn fields_for(&self, vault: VaultId) -> impl Iterator<Item = &str> {
        self.mapping
            .iter()
            .filter(move |(_, v)| **v == vault)
            .map(|(name, _)| name.as_str())
    }
}

fn is_valid_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ShatterSchema {
        ShatterSchema::new(
            1,
            [
                ("name", VaultId::A),
                ("birth_year", VaultId::B),
                ("card_number", VaultId::C),
            ],
        )
        .expect("valid schema")
    }

    #[test]
    fn maps_fields_to_vaults() {
        let s = sample();
        assert_eq!(s.version(), 1);
        assert_eq!(s.vault_for("name"), Some(VaultId::A));
        assert_eq!(s.vault_for("card_number"), Some(VaultId::C));
        assert_eq!(s.vault_for("unknown"), None);
        assert_eq!(s.fields_for(VaultId::B).collect::<Vec<_>>(), ["birth_year"]);
    }

    #[test]
    fn rejects_invalid_schemas() {
        let err = Some(ShatterError::InvalidSchema);
        assert_eq!(ShatterSchema::new(0, [("a", VaultId::A)]).err(), err);
        assert_eq!(
            ShatterSchema::new(1, Vec::<(&str, VaultId)>::new()).err(),
            err
        );
        assert_eq!(ShatterSchema::new(1, [("", VaultId::A)]).err(), err);
        assert_eq!(ShatterSchema::new(1, [("a-b", VaultId::A)]).err(), err);
        assert_eq!(
            ShatterSchema::new(1, [("a", VaultId::A), ("a", VaultId::B)]).err(),
            err
        );
    }

    #[test]
    fn converts_from_raw_form() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), 'a');
        let s = ShatterSchema::try_from(RawSchema { version: 2, fields }).expect("valid");
        assert_eq!(s.version(), 2);
        assert_eq!(s.vault_for("name"), Some(VaultId::A));
    }

    #[test]
    fn raw_form_rejects_unknown_vault_label() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), 'Z');
        let result = ShatterSchema::try_from(RawSchema { version: 1, fields });
        assert_eq!(result.err(), Some(ShatterError::UnknownVault));
    }
}
