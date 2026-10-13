# tpt-shatter-assembler

The read-side counterpart to the [shredder](../tpt-shatter-shredder/). The assembler fetches the three fragments for a shard, checks them, and rebuilds the record in memory. It never returns a partial record.

The crate also re-shatters a shard from one schema version to another, which is how a schema changes without losing data.

> **Status:** implemented and tested. Not published to crates.io (`publish = false`). Several hardening items are still open (see [Limitations](#limitations)).

## Contents

- [What it provides](#what-it-provides)
- [How assembly works](#how-assembly-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Migration](#migration)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `Assembler::new(schema, router, derivation_key)` | Builds an assembler over a schema and router. |
| `Assembler::assemble(shard)` | Fetches all three fragments in parallel and returns the `Record`. |
| `assemble_with_deadline(schema, router, derivation_key, shard, deadline)` | As `assemble`, but fails with `VaultUnavailable` if any vault has not answered by the deadline. |
| `migrate_shard(from, to, router, derivation_key, shard)` | Rewrites one shard's fragments from one schema version to another, in place. |

## How assembly works

1. **Derive.** For each vault, the fragment ID is derived from the shard key. The key is used only on the calling thread.
2. **Fetch in parallel.** Each vault is read on its own thread through the router.
3. **Check every fragment.** A missing fragment returns `Reconstruction`. A failed read returns that vault's error. Nothing is returned until all three are present.
4. **Rebuild.** The fragments are decoded and merged under the schema. A field found in the wrong vault is an error.

With a deadline, step 2 is bounded. A vault call cannot be interrupted, so a fetch that misses the deadline keeps running in the background. Its result is dropped when it arrives, and its bytes are zeroed then.

## Installation

```toml
[dependencies]
tpt-shatter-assembler = { path = "../tpt-shatter-assembler" }
```

## Quick start

```rust
use tpt_shatter_assembler::Assembler;

let assembler = Assembler::new(&schema, &router, derivation_key);
let record = assembler.assemble(&shard)?;
let name = record.get("name");
```

`schema` and `router` come from the surrounding service. The examples below build a complete setup with in-memory vaults.

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`assemble_and_migrate`](examples/assemble_and_migrate.rs) | Shredding and reassembling a record, the deadline variant, and a schema migration that moves a field to another vault. | `cargo run -p tpt-shatter-assembler --example assemble_and_migrate` |

## Migration

`migrate_shard(from, to, ...)` moves one shard to a new schema. It works like this:

- **Fragments are rewritten in place.** The old version is retired by the write that replaces it.
- **Each fragment is read under its own version.** A shard left half-migrated by an earlier failure still reads correctly.
- **A failed run is safe to repeat.** Running it again finishes the work. The migration does not use the shredder's compensation path, because that would delete the new-version data it had just written.

Use this when a field moves between vaults or a schema version changes. Migrate shards in batches, and check reassembly afterwards.

**Order matters.** `assemble` refuses a fragment whose version header differs from the schema it is given. Switch readers to the new schema only after a shard has migrated. Until then, reading an unmigrated shard under the new schema fails with `Reconstruction`, as it should.

## Security properties

- **Fail closed.** A missing, malformed, or misplaced fragment returns an error. A partial record is never returned.
- **Derivation key stays on one thread.** Only fragment IDs cross to the fetch threads.
- **Bounded waiting.** `assemble_with_deadline` returns within its deadline, so one slow vault cannot hold a request open.
- **Late results are discarded.** Bytes from a fetch that missed its deadline are zeroed when dropped.

## Limitations

- **No memory locking.** `mlock` and `RLIMIT_CORE` hardening are not implemented, so reconstructed values may be written to swap or a core dump.
- **No internal transport.** The gRPC interface with mTLS is not implemented. Assembly runs in-process.
- **No static build.** The statically linked musl build is not set up. It needs Linux host work.
- **Deadline-bounded fetches keep running.** A vault call that misses the deadline cannot be cancelled, so it finishes in the background.
- **Migration is not atomic across a shard.** Each fragment is rewritten separately. The shard is readable at every step, but it is not switched to the new version in one operation.

## Testing

```sh
cargo test -p tpt-shatter-assembler
```

The integration tests in [`tests/pipeline.rs`](tests/pipeline.rs) run the whole path with synthetic data: shred, assemble, emit with the anonymization policy, detect a canary read, and erase. Unit tests cover the rebuild rules and migration.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
