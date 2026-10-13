// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Data fragmentation for tpt-shatter.
//!
//! [`Shredder::shred`] splits a record into one fragment per vault according to a
//! [`ShatterSchema`](tpt_shatter_common::ShatterSchema), writes them in parallel,
//! and compensates partial failures. [`erase`] removes every fragment for a shard
//! (GDPR erasure).
//!
//! Not implemented yet: the internal ingestion service with mTLS and RAM-only key loading.
//! The orphan queue is durable when built with [`Shredder::with_orphan_log`]. Background
//! reaping is [`run_reaper`].

mod erase;
mod orphans;
mod reaper;
mod shred;

pub use erase::{EraseReport, erase};
pub use orphans::OrphanStore;
pub use reaper::run_reaper;
pub use shred::{ReapReport, ShredReport, Shredder};
