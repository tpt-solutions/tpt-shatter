# tpt-shatter-shredder

The write-side fragmentation engine for tpt-shatter. The shredder takes one record, splits it by field into one fragment per vault, writes them in parallel, and undoes its own partial writes if anything fails. It also erases every fragment for a shard on request, and retries deletes that did not finish.

The shredder holds no mapping table. Fragment IDs are re-derived from the shard key, so the [assembler](../tpt-shatter-assembler/) can find the fragments again without a lookup.

> **Status:** implemented and tested. Not published to crates.io (`publish = false`). The internal ingestion service is not part of this crate yet.

## Contents

- [What it provides](#what-it-provides)
- [How a shred works](#how-a-shred-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Erasure](#erasure)
- [Orphans and the reaper](#orphans-and-the-reaper)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `Shredder::new(schema, router, derivation_key)` | A shredder whose orphan queue lives in memory. |
| `Shredder::with_orphan_log(...)` | As above, with the orphan queue backed by a file, so it survives a restart. |
| `Shredder::with_store(...)` | Several shredders over one shared orphan store, so ingestion and the reaper see one queue. |
| `Shredder::shred(shard, record)` | Writes one fragment per vault. Returns `ShredReport { fragments_written }`. |
| `Shredder::reap(max_attempts)` | Retries queued orphan deletes once. Returns `ReapReport { removed, still_pending, abandoned }`. |
| `Shredder::pending_orphans()` | The number of orphans waiting for a reap. |
| `erase(router, derivation_key, shard)` | Deletes every fragment for a shard. Returns `EraseReport { rows_removed, verified }`. |
| `run_reaper(shredder, interval, max_attempts, stop, alerts, on_report)` | Runs `reap` on an interval until a stop flag is set. |
| `OrphanStore` | The orphan queue, in memory or in a JSON-lines file. |

## How a shred works

1. **Validate.** Every field of the record must appear in the schema. If one does not, nothing is written and `InvalidSchema` is returned.
2. **Plan.** Each vault gets exactly one fragment, even if the record has no fields for it. A missing fragment can then be detected at reassembly.
3. **Write in parallel.** Each fragment is written to its vault under the schema version header.
4. **Compensate.** If any write fails, the fragments already written are deleted and the original error is returned.
5. **Queue what cannot be undone.** If a compensating delete also fails, that fragment becomes an orphan, to be retried by `reap`.

A retry of the whole shred is safe. Fragment IDs are deterministic and puts replace their target, so running the same shred twice leaves the same state.

## Installation

```toml
[dependencies]
tpt-shatter-shredder = { path = "../tpt-shatter-shredder" }
```

## Quick start

```rust
use tpt_shatter_common::{Record, ShardKey};
use tpt_shatter_shredder::Shredder;

let shredder = Shredder::new(&schema, &router, derivation_key);
let mut record = Record::new();
record.insert("name", "Synthetic Person");
let report = shredder.shred(&ShardKey::from_bytes([0x42; 32]), record)?;
assert_eq!(report.fragments_written, 3);
```

`schema` and `router` come from the surrounding service. The [examples](examples/) show a complete setup with in-memory vaults.

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`shred_and_erase`](examples/shred_and_erase.rs) | Shredding a record across three vaults, counting rows per vault, erasing the shard, and running a reap. | `cargo run -p tpt-shatter-shredder --example shred_and_erase` |

## Erasure

`erase(router, derivation_key, shard)` removes every fragment for a shard across all three vaults. It implements the GDPR erasure path.

- **Idempotent.** Deleting a missing fragment is not an error. A repeat call returns `rows_removed: 0`, and running it again after a failure finishes the job.
- **Verified.** After deletion, the call reads back each fragment ID. `verified` is `true` only when none of them is present.
- **Not observed.** Erasure uses maintenance access, so it cannot trigger a canary alarm.
- **Errors stop the run.** A vault error returns immediately. Call `erase` again to finish.

## Orphans and the reaper

An orphan is a fragment whose delete failed and must be retried. The reaper is the component that retries them.

- `reap(max_attempts)` retries each queued orphan once. Each orphan that still fails is kept and its attempt count rises. An orphan that reaches `max_attempts` is dropped and counted as `abandoned`, which means it needs an operator.
- `run_reaper` calls `reap` on an interval, reports each pass through a callback, and stops when its flag is set.
- **Durability depends on the constructor.** `Shredder::new` keeps the queue in memory, so a restart loses it. `Shredder::with_orphan_log` writes new orphans to a JSON-lines file before queuing them, and loads the file on start. Attempt counts are not stored, so after a restart every orphan starts again at zero.

Orphan records hold a vault label and a fragment ID. A fragment ID reveals nothing without the derivation key, and field values are never written to the orphan file.

## Security properties

- **No mapping table.** Nothing records which fragments belong to which shard. Only the derivation key links them.
- **Fields are dropped after use.** The record is consumed by `shred`, and its values are zeroed when it is dropped.
- **Derivation key is zeroed on drop.** It is held in memory for the shredder's lifetime.
- **Partial writes are undone.** A failed shred does not leave a half-written record behind, except for the orphans described above, which are retried.
- **Erasure is checked.** The read-back in `erase` catches a fragment that survived deletion.

## Limitations

- **Compensation is best effort.** If a compensating delete fails and the orphan log is not in use, a restart loses the orphan. The fragment then stays in its vault until the retention purge removes it.
- **Abandoned orphans need a person.** The reaper never gives up silently, but it does drop an orphan after `max_attempts`. Operators must watch for abandoned orphans.
- **Backups are not covered.** `erase` removes live fragments only. Backups are handled outside this crate.
- **No ingestion service yet.** The shredder is a library. The internal ingestion service with mTLS is not implemented.
- **Overwrite behavior is the vault's.** Erasure relies on the vault's delete, which overwrites in place on the file vault. The vault client's documentation covers what that does and does not guarantee.

## Testing

```sh
cargo test -p tpt-shatter-shredder
```

Tests cover one fragment per vault, rejection of fields outside the schema before any write, compensation after a partial failure, retry after recovery, idempotent erasure, orphans queued during failed compensation and reaped once a vault recovers, abandonment after `max_attempts`, orphans surviving a restart through the log file, and the reaper's reporting, alerting on abandoned orphans, and stop behavior.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
