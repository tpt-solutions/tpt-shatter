// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The public read path: token checks, rate limiting, uniform errors, key rotation
//! on canary alarms, readiness, and access logs.
//!
//! [`Gateway::read`] is transport-neutral. It takes a token and a shard in hex and
//! returns a [`Response`]. The HTTP server is not in this crate yet. The axum and
//! tonic dependencies need a license-policy decision first (see the checklist).
//!
//! The gateway does not depend on the vault client. It reaches records only through
//! the [`RecordSource`] trait, which the assembler will implement.

mod ratelimit;
mod service;

pub use ratelimit::RateLimiter;
pub use service::{
    AlarmResponder, Gateway, RecordSource, Response, SigningKeyRotator, public_error, ready,
};
