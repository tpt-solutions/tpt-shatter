// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

/// A reconstructed record, held in RAM only.
///
/// Field values are zeroed on drop. The type has no `Clone`, and its `Debug`
/// output lists field names only, never values.
#[derive(Default)]
pub struct Record {
    fields: BTreeMap<String, Zeroizing<String>>,
}

impl Record {
    /// Creates an empty record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a field. Returns the previous value if the field already existed.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Option<Zeroizing<String>> {
        self.fields
            .insert(name.into(), Zeroizing::new(value.into()))
    }

    /// Returns a field value. Callers must not log it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|v| v.as_str())
    }

    /// Iterates over field names in sorted order.
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the record has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_reads_fields() {
        let mut r = Record::new();
        assert!(r.is_empty());
        assert!(r.insert("name", "A. Example").is_none());
        assert_eq!(r.get("name"), Some("A. Example"));
        assert_eq!(r.len(), 1);
        assert_eq!(r.get("missing"), None);
    }

    #[test]
    fn debug_lists_names_not_values() {
        let mut r = Record::new();
        r.insert("ssn", "123-45-6789");
        let shown = format!("{r:?}");
        assert!(shown.contains("ssn"));
        assert!(!shown.contains("123-45-6789"));
    }

    #[test]
    fn field_names_are_sorted() {
        let mut r = Record::new();
        r.insert("zip", "1");
        r.insert("age", "2");
        let names: Vec<_> = r.field_names().collect();
        assert_eq!(names, ["age", "zip"]);
    }
}
