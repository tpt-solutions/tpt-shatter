# tpt-shatter-canary

Canary (honeytoken) records for tpt-shatter. A canary is a synthetic record that is planted in the vaults and that nothing legitimate ever reads. If one is read or deleted, something has gone wrong, and the crate turns that access into an alarm and runs a response.

The canaries look like real records, so a person or a script that browses a vault has no easy way to tell them apart.

> **Status:** implemented and tested. Not published to crates.io (`publish = false`).

## Contents

- [What it provides](#what-it-provides)
- [How detection works](#how-detection-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [The alarm response](#the-alarm-response)
- [Rotation](#rotation)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `CanaryPlan` | The canaries for one epoch: a secret canary key and a count. Derives each canary's shard key and record. |
| `CanaryRotation` | The schedule. Maps a time to an epoch, gives that epoch's plan, and says whether a refresh is due. |
| `refresh_canaries` | Writes the current epoch's canaries into the vaults and removes the previous epoch's. |
| `CanaryWatch` | An `AccessObserver` attached to the router. Queues an `Alarm` for each observed read or delete of a canary. |
| `CanaryMonitor` | Drains the watch, runs the alarm gate, and writes each alarm to the alert log. |
| `Detector` | Recognizes canary fragment IDs in a set of queried IDs. Used by the watch. |
| `AlarmGate` | Turns detections into one response, then disarms until a cooldown passes or a person re-arms it. |
| `Responder` | Trait with the two response steps: `rotate_signing_key` and `notify_security`. |
| `Alarm` | One detection: the vault and the canary's index. Nothing else. |
| `values::canary_value` | Produces realistic-looking field values from a field name, so the canary shape matches the schema. |

## How detection works

1. Each canary is a record derived from the canary key. Its shard key and fragment IDs are derived in turn, so the same plan always gives the same canaries.
2. The planted fragments are written through the shredder, as real records are.
3. The router reports every observed read and delete to the watch.
4. The watch checks each access against the current canary IDs. A match becomes an alarm.
5. The monitor passes alarms to the gate. The gate runs the response once, then suppresses further alarms until the cooldown has passed.

Writes are not observed, and neither are the router's maintenance methods. Planting, rotation, erasure, and reaping therefore never trip a canary.

## Installation

```toml
[dependencies]
tpt-shatter-canary = { path = "../tpt-shatter-canary" }
```

## Quick start

```rust
use std::sync::Arc;
use tpt_shatter_canary::{CanaryRotation, CanaryWatch, refresh_canaries};

let rotation = CanaryRotation::new(master_key, derivation_key, 3, 604_800)?; // weekly, 3 canaries
let plan = rotation.plan_at(now)?;
let watch = Arc::new(CanaryWatch::new(&plan)?);
let router = Router::new(guards)?.with_observer(watch.clone());

refresh_canaries(&rotation, &schema, &router, &derivation_key, None, now)?;
```

The watch is built from the same plan that is planted, so the two always agree. After each later rotation, call `CanaryWatch::replace` with the new plan.

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`detect_canary_access`](examples/detect_canary_access.rs) | Planting canaries, a normal read that raises no alarm, a canary read that does, the monitor's response, and the cooldown. | `cargo run -p tpt-shatter-canary --example detect_canary_access` |

## The alarm response

The response has two steps, supplied by the `Responder` implementation:

- **Rotate the signing key.** Every outstanding capability token stops verifying at once. An attacker holding a token that was in use cannot keep using it.
- **Notify security.** The alert is written to the security alert log and handed to the notifier.

`AlarmGate` runs these once, then disarms. Later alarms within the cooldown are counted as `Suppressed`, so a flood of reads cannot trigger repeated rotations. If the response fails, the gate stays armed, so the next poll retries it.

Re-arming is a deliberate step. `AlarmGate::rearm` and `CanaryMonitor::rearm` refuse until the cooldown has passed, and a person is expected to look at the alert before the gate is re-armed in production.

Each alert records only the vault and the canary index. The alarm's `Debug` output contains no identifiers and no values.

## Rotation

`CanaryRotation` divides time into epochs of `period_secs`. The canary key for an epoch is derived from the master key and the epoch number, so:

- the canaries for an epoch are stable for that whole epoch;
- they change completely at the next epoch;
- `needs_refresh(last_epoch, now)` says whether the vaults need new canaries.

`refresh_canaries` does nothing while the epoch is unchanged, writes a new set when it moves, and removes the previous epoch's canaries. It returns `Some(epoch)` when it refreshed and `None` when no refresh was due.

After every refresh, the caller must call `CanaryWatch::replace` with the new plan. Otherwise the watch keeps looking for the old canaries, and the new ones go unwatched.

## Security properties

- **Secret canaries.** Canary records and their IDs come from the canary key. Only holders of that key can tell which records are canaries.
- **Realistic values.** Field values are shaped by field name, so a card-like field holds a Luhn-valid number and an email field uses the RFC 2606 `.invalid` domain.
- **Minimal alarm data.** An alarm carries a vault and an index. Canary values, shard keys, and fragment IDs stay out of the alert log.
- **Response is rate limited.** The gate's cooldown prevents a flood of accesses from causing a flood of rotations.
- **Detection does not depend on the caller.** Once attached to the router, the watch sees every observed access, regardless of which component made it.

## Limitations

- **Overwrites are not detected.** Only reads and deletes are observed. A canary that is overwritten with a write goes unnoticed. Writes are unobserved because ingestion writes real data through the same router.
- **Direct file access is not seen.** Anyone with access to the vault files on disk, or any code that bypasses the router, is outside the watch.
- **Card-like canaries can match real cards by chance.** The card values are not drawn from a test range, so one can match a real number. They are stored only in the vaults and never leave them, which limits the exposure.
- **The watch must be replaced after rotation.** Forgetting `CanaryWatch::replace` leaves the new canaries unwatched. This is the most important operational step to get right.
- **Alarm delivery depends on the responder.** The notifier is a trait. This crate writes the alert log, but paging a person is the responder's job.

## Testing

```sh
cargo test -p tpt-shatter-canary
```

Tests cover deterministic and secret-dependent plans, epoch rotation and refresh, field-shaped values, detection of canary fragments and not real ones, alarm log contents, the gate firing once and then suppressing, failed responses staying armed for retry, and re-arming only after the cooldown.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
