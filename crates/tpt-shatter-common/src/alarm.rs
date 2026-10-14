// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Canary alarms and the responder that acts on them.
//!
//! These live in the common crate, not the canary crate, so the gateway can implement
//! a responder without depending on canary (and, through it, on the vault client).

use crate::{AlertLog, ShatterError, VaultId};

/// One canary found in a query.
///
/// The alarm holds only the vault and canary index. It never holds the FragmentId or
/// any canary value, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alarm {
    /// The vault that was queried.
    pub vault: VaultId,
    /// Which canary was touched.
    pub index: usize,
}

impl Alarm {
    /// Writes this alarm to the security alert log at time `at` (Unix seconds).
    ///
    /// Only the vault label and canary index are written. A responder calls this from
    /// [`Responder::notify_security`] to implement the notification channel.
    pub fn record(&self, log: &AlertLog, at: u64) -> Result<(), ShatterError> {
        let index = self.index.to_string();
        log.append(
            "canary_alarm",
            at,
            &[
                ("vault", &self.vault.label().to_string()),
                ("index", &index),
            ],
        )
    }
}

/// The side effects an alarm triggers.
pub trait Responder {
    /// Rotates the token signing key, invalidating every outstanding token.
    fn rotate_signing_key(&self) -> Result<(), ShatterError>;
    /// Sends one alarm to security. The alarm carries no canary values.
    fn notify_security(&self, alarm: &Alarm) -> Result<(), ShatterError>;
}
