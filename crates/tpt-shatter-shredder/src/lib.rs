// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Data fragmentation for tpt-shatter.
//!
//! [`Shredder::shred`] splits a record into one fragment per vault according to a
//! [`ShatterSchema`](tpt_shatter_common::ShatterSchema), writes them in parallel,
//! and compensates partial failures. [`erase`] removes every fragment for a shard
//! (GDPR erasure).
//!
//! Not implemented yet: the internal ingestion service with mTLS, RAM-only key loading,
//! and durable storage for the orphan queue (it is in RAM only).

mod erase;
mod orphans;
mod shred;

pub use erase::{EraseReport, erase};
pub use shred::{ShredReport, Shredder};
