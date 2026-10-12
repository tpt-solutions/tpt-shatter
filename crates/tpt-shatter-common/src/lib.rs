// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Shared types, traits, and error definitions for tpt-shatter.
//!
//! This crate contains no business logic. Sensitive types here never implement
//! `Clone` or a revealing `Debug`, and their `Debug` output is redacted.

mod error;
mod fragment_id;
mod payload;
mod record;
mod schema;
mod shard_key;
mod token;
mod vault;
mod zero;

pub use error::ShatterError;
pub use fragment_id::{FRAGMENT_ID_LEN, FragmentId};
pub use payload::FragmentPayload;
pub use record::Record;
pub use schema::ShatterSchema;
pub use shard_key::{SHARD_KEY_LEN, ShardKey};
pub use token::{CapabilityToken, DEFAULT_TOKEN_TTL_SECS, Scope, Scopes};
pub use vault::VaultId;
pub use zero::SecureZero;
