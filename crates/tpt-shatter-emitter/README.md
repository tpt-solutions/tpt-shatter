# tpt-shatter-emitter

The last stage before data leaves the trusted core. The emitter takes reconstructed records, applies a per-field anonymization policy, checks the whole batch against a k-anonymity gate, and only then writes the results to a sink.

Anything the policy does not name is dropped. Unexpected fields therefore never reach an analytics sink, even if a record carries them.

> **Status:** implemented and tested. Not published to crates.io (`publish = false`). The analytics adapter is built on a pinned `tpt-strata` revision; see [UPSTREAM.md](../../UPSTREAM.md) for the upstream facts it depends on.

## Contents

- [What it provides](#what-it-provides)
- [How emission works](#how-emission-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Writing a policy](#writing-a-policy)
- [Sinks](#sinks)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `Policy::new(salt, rules, quasi_identifiers, k)` | Validates and builds the policy. |
| `Transform` | What happens to one field: `Drop`, `Mask { keep_last }`, `Bucket { width }`, `Pseudonymize`, or `Noise { sensitivity, epsilon }`. |
| `Policy::transform(record)` | Anonymizes one record into an `Event`. Fields without a rule are omitted. |
| `Event` | An anonymized record: `get(name)`, `len()`, `is_empty()`. |
| `Emitter::new(policy, sink)` | Pairs a policy with a sink. |
| `Emitter::emit(records)` | Transforms the whole batch, checks k-anonymity, then emits. Returns `EmitReport { emitted }`. |
| `EventSink` | Trait for a destination. |
| `MemorySink` | Keeps events in memory, for tests and short-lived use. |
| `JsonlSink` | Appends events to a JSON-lines file. `read_all` reads them back. |
| `StrataSink` | Analytics adapter. Writes to a `JsonlSink` first, then serves grouped aggregates from memory. |

## How emission works

1. **Transform every record.** Each field is passed through its rule. Fields with no rule are left out.
2. **Count cohorts.** The quasi-identifier values of the transformed events are grouped.
3. **Gate the batch.** If any cohort has fewer than `k` members, the whole batch is refused and nothing is emitted.
4. **Emit.** The events go to the sink in one batch.

The gate runs before any write, so a refused batch leaves no partial output.

## Installation

```toml
[dependencies]
tpt-shatter-emitter = { path = "../tpt-shatter-emitter" }
```

## Quick start

```rust
use tpt_shatter_emitter::{Emitter, MemorySink, Policy, Transform};

let policy = Policy::new(
    salt,                                              // secret, from a secret store
    [
        ("name".to_owned(), Transform::Pseudonymize),
        ("birth_year".to_owned(), Transform::Bucket { width: 10 }),
        ("card_number".to_owned(), Transform::Mask { keep_last: 4 }),
    ],
    vec!["birth_year".to_owned()],                     // quasi-identifiers
    5,                                                 // k
)?;

let emitter = Emitter::new(policy, MemorySink::new());
let report = emitter.emit(records)?;
```

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`policy_and_k_anonymity`](examples/policy_and_k_anonymity.rs) | A full policy, dropped fields, a durable JSON-lines sink, and the gate refusing a batch with a small cohort. | `cargo run -p tpt-shatter-emitter --example policy_and_k_anonymity` |

## Writing a policy

- **Name every field you want.** A field with no rule is dropped. This is the safe default, and it is the reason the emitter is an allow-list.
- **Choose transforms by what the analysis needs.** `Bucket` keeps ranges for age-style analysis. `Pseudonymize` keeps joinability without the identifier. `Mask` keeps a recognizable suffix. `Noise` releases a numeric value with differential privacy for one query.
- **Make quasi-identifiers coarse.** A quasi-identifier must have a rule other than `Drop`, and it should be generalized (for example, bucketed) so that cohorts can reach `k`.
- **Keep `k` honest.** Set `k` for the smallest group you are willing to release. A `k` of one disables the protection.

`Policy::new` rejects an empty salt, a zero `k`, a non-positive bucket width, and a quasi-identifier that has no rule or is dropped.

## Sinks

- **`MemorySink`** is for tests and for code that reads the events itself.
- **`JsonlSink`** is the durable record. It appends, so reopening the file keeps earlier events. Reading a malformed line fails the whole read rather than skipping it.
- **`StrataSink`** holds the analytics view. Every event is written to a `JsonlSink` first, then kept in memory as a tpt-strata table. Opening it replays the log, so a restart rebuilds the view. It exposes only grouped aggregates (`count_by`, `sum_by`), never whole tables.

Summing a non-numeric field is refused.

## Security properties

- **Allow-list output.** Only the fields a policy names can leave the emitter.
- **No raw identifiers in output.** Names are pseudonymized, birth years are bucketed, and card numbers are masked. The test suite checks that no raw identifier appears in the output.
- **Refusal is atomic.** A batch that fails the gate leaves the sink untouched.
- **Salt is zeroized.** The policy holds the salt in zeroizing memory.
- **Analytics expose aggregates only.** The Strata adapter cannot return individual rows.

## Limitations

- **The gate checks cohorts, not attributes.** k-anonymity stops small groups from being singled out. It does not stop a sensitive value shared by a large group from being disclosed.
- **Noise is per query.** `Noise` adds Laplace noise to one value. The emitter does not track a privacy budget across batches, so repeated releases spend privacy with nothing to stop them.
- **The Strata view is in memory.** It is rebuilt from the log on start, so memory grows with the log. Plan for that volume.
- **tpt-strata is in-memory and not durable.** [UPSTREAM.md](../../UPSTREAM.md) records that strata cannot be the durable copy of anonymized events, which is why every event goes to the JSON-lines log first. The dependency is pinned to one git revision, and its API should be re-checked before any upgrade.
- **`Transform::Noise` is limited to numeric input.** A non-numeric value under a noise rule is refused.

## Testing

```sh
cargo test -p tpt-shatter-emitter
```

Tests cover the absence of raw identifiers in output, stable pseudonyms, noise staying numeric, dropping of unruled fields, the batch-wide k gate in both directions, policy validation, JSON-lines round trips and reopening, malformed-line handling, grouped counts and sums, rejection of non-numeric sums, and rebuilding the Strata view after a restart.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
