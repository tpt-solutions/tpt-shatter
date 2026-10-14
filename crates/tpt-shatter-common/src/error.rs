// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

use thiserror::Error;

use crate::vault::VaultId;

/// Unified error type for tpt-shatter.
///
/// Messages are fixed strings and variants carry no payload data, so an error
/// can be displayed or logged without leaking records, fragments, or keys.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ShatterError {
    /// A shard key or fragment ID was malformed (wrong length or encoding).
    #[error("invalid shard key")]
    InvalidShardKey,
    /// A capability token was malformed or failed verification.
    #[error("invalid capability token")]
    InvalidToken,
    /// A capability token is past its time-to-live.
    #[error("capability token expired")]
    TokenExpired,
    /// The token does not grant the requested scope.
    #[error("unauthorized")]
    Unauthorized,
    /// A vault label did not name a known vault.
    #[error("unknown vault")]
    UnknownVault,
    /// A shatter schema failed validation.
    #[error("invalid shatter schema")]
    InvalidSchema,
    /// A vault could not be reached or did not answer in time.
    #[error("vault unavailable")]
    VaultUnavailable {
        /// The vault that failed.
        vault: VaultId,
    },
    /// A record could not be reconstructed from its fragments.
    #[error("record reconstruction failed")]
    Reconstruction,
    /// A numeric or structural parameter was out of range (for example epsilon <= 0).
    #[error("invalid parameter")]
    InvalidParameter,
    /// A cohort is smaller than the configured k-anonymity threshold.
    #[error("k-anonymity threshold not met")]
    KAnonymityViolation,
    /// A caller exceeded its request budget.
    #[error("rate limited")]
    RateLimited,
    /// A service this one depends on, such as the assembler, could not be reached or did not
    /// answer in time.
    #[error("service unavailable")]
    ServiceUnavailable,
    /// An unexpected internal failure.
    #[error("internal error")]
    Internal,
}
