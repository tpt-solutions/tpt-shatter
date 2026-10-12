// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Client library for the isolated vaults, plus the fragment wire format and
//! keyed FragmentId derivation shared by the shredder and assembler.
//!
//! Every operation names exactly one vault and one [`FragmentId`](tpt_shatter_common::FragmentId).
//! There is no query path that spans vaults, so cross-vault joins are impossible
//! at this layer.
//!
//! Not implemented yet: a real tpt-keystone-db backend (Postgres wire client with
//! TLS and SCRAM), connection pooling, and per-request timeouts. The in-memory
//! backend stands in for them in tests.

mod backend;
mod codec;
mod derive;
mod guard;
mod router;

pub use backend::{MemoryVault, VaultBackend};
pub use codec::{add_schema_version, decode_fields, encode_fields, split_schema_version};
pub use derive::{derive_fragment_id, keyed_digest};
pub use guard::{BreakerConfig, BreakerState, Clock, Guarded, VaultStatus, system_clock};
pub use router::Router;
