// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The public read path: token checks, rate limiting, uniform errors, key rotation
//! on canary alarms, readiness, and access logs.
//!
//! [`Gateway::read`] is transport-neutral. It takes a token and a shard in hex and
//! returns a [`Response`]. [`serve`] wraps it in an HTTP/1.1 server (hyper, MIT). The
//! gRPC transport was dropped; see `DECISIONS.md`.
//!
//! The gateway does not depend on the vault client. It reaches records only through
//! the [`RecordSource`] trait, which the assembler will implement.

mod http;
mod ingest;
pub mod remote;
mod ratelimit;
mod service;
mod tls;

pub use http::{AccessLog, BreakerProbe, HttpConfig, Shared, WriteHandler, serve, serve_tls};
pub use ingest::{RecordSink, Writer};
pub use ratelimit::RateLimiter;
pub use remote::RemoteAssembler;
pub use service::{
    AccessAudit, AlarmResponder, Gateway, RecordSource, Response, SigningKeyRotator, public_error,
    ready,
};
pub use tls::{acceptor, server_config};
