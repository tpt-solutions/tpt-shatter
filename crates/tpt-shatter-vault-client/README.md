# tpt-shatter-vault-client

The client side of tpt-shatter's isolated vaults. It holds the fragment wire format, derives fragment IDs from keys, routes every operation to exactly one vault behind a circuit breaker, and provides the encrypted on-disk storage each vault uses.

The point of the layer is that no call can span vaults. A caller that holds the router can reach one vault per call, so cross-vault joins cannot be written against this API.

> **Status:** implemented and tested. Not published to crates.io (`publish = false`).

## Contents

- [What it provides](#what-it-provides)
- [How a fragment is addressed](#how-a-fragment-is-addressed)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Observed and maintenance access](#observed-and-maintenance-access)
- [Circuit breakers](#circuit-breakers)
- [File vault](#file-vault)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `VaultBackend` | Trait for one vault's storage: `put`, `get`, and `delete` by `FragmentId`. |
| `MemoryVault` | In-memory backend for tests. `set_available(false)` simulates an outage to exercise failure paths. |
| `FileVault` | Encrypted, one-file-per-fragment backend. Supports `purge_expired` for retention. |
| `Guarded` | Wraps a backend with a circuit breaker and retry policy. |
| `BreakerConfig`, `BreakerState`, `VaultStatus` | Breaker tuning, the `Closed` / `Open` / `HalfOpen` states, and a snapshot for readiness probes. |
| `Router` | Holds one `Guarded` per vault and routes each call to exactly one of them. |
| `AccessObserver`, `Access` | Hook that sees every observed read and delete before it happens. Used for canary detection. |
| `derive_fragment_id`, `keyed_digest` | Keyed HMAC-SHA256 derivation of fragment IDs, with a domain tag per vault. |
| `encode_fields`, `decode_fields` | The fragment body format: a sequence of length-prefixed name and value pairs. |
| `add_schema_version`, `split_schema_version` | A 4-byte big-endian schema version header, so a reader knows which schema wrote a fragment. |

## How a fragment is addressed

A fragment's ID is an HMAC-SHA256 keyed by the derivation key, computed over the vault's domain tag and the shard key's bytes. The same shard has a different ID in each vault, so a vault cannot tell which of its fragments belong to the same record, and it cannot work out the ID without the derivation key.

On the wire, a fragment body is the schema version header followed by the encoded fields.

## Installation

```toml
[dependencies]
tpt-shatter-vault-client = { path = "../tpt-shatter-vault-client" }
```

## Quick start

```rust
use tpt_shatter_common::{ShardKey, VaultId};
use tpt_shatter_vault_client::{
    BreakerConfig, Guarded, MemoryVault, Router, add_schema_version, derive_fragment_id,
    encode_fields, system_clock,
};

let guards = VaultId::ALL
    .into_iter()
    .map(|v| Guarded::new(Box::new(MemoryVault::new(v)), BreakerConfig::default(), system_clock()))
    .collect();
let router = Router::new(guards)?;

let shard = ShardKey::from_bytes([0x10; 32]);
let id = derive_fragment_id(&[0xA1; 32], &shard, VaultId::A)?;
let body = add_schema_version(1, &encode_fields([("name", "Synthetic Person")])?);
router.put(VaultId::A, &id, &body)?;
let stored = router.get(VaultId::A, &id)?;
```

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`router_and_file_vault`](examples/router_and_file_vault.rs) | Wire format, keyed IDs, a router over three vaults with breaker status, and an encrypted file vault with retention. | `cargo run -p tpt-shatter-vault-client --example router_and_file_vault` |

## Observed and maintenance access

The router has two kinds of method, and the difference matters for canary detection:

- **Observed methods** (`get`, `delete`) are the normal access path. An attached `AccessObserver` sees each call before it runs.
- **Maintenance methods** (`get_maintenance`, `delete_maintenance`, `contains_maintenance`) are for internal work: erasure, canary rotation, compensation after a failed write, and orphan reaping. They are not observed, so that internal work cannot trigger a canary alarm.

Anyone who holds the router can call the maintenance methods. Keep the router's ownership inside the trusted crates.

## Circuit breakers

`Guarded` wraps each backend. The defaults are:

| Setting | Default | Meaning |
| --- | --- | --- |
| `failure_threshold` | 5 | Consecutive failed operations before the breaker opens. |
| `cooldown_secs` | 30 | Seconds the breaker stays open before it allows a trial call. |
| `attempts` | 2 | Total attempts per operation. Retries are immediate; backoff is not implemented yet. |

While a breaker is open, calls fail fast with `VaultUnavailable` instead of waiting on a failing vault. The gateway's `/readyz` reports whether any breaker is open.

## File vault

`FileVault::open(vault, dir, key)` stores each fragment as one encrypted file:

- **Encryption.** Each fragment is sealed with ChaCha20-Poly1305 under the vault's own key. The associated data is the vault label, the fragment ID, and the stored-at time. A file moved to another vault or ID, or with its timestamp changed, fails to open.
- **Layout.** `nonce (12 bytes) || stored_at (8 bytes, big-endian Unix seconds) || sealed`.
- **Atomic writes.** A put writes a temporary file, syncs it, and renames it into place. A crash leaves the old or the new contents, never a partial file.
- **Retention.** `purge_expired(policy, now)` erases fragments older than the policy and reports how many it removed and how many were malformed.
- **Erasure on delete.** A delete overwrites the file with zeros, syncs, and then removes it.

## Security properties

- **No cross-vault query.** Every method names one vault. Nothing in the API can join across vaults.
- **Keyed identifiers.** Fragment IDs are HMAC outputs, not hashes of the data, so they reveal nothing without the derivation key.
- **Per-vault keys.** Each file vault has its own encryption key, supplied by the caller and held in memory.
- **Authenticated storage.** A tampered, misplaced, or renamed file fails to decrypt rather than returning wrong bytes.
- **Fail closed.** A breaker that is open returns an error. Nothing is served from a stale cache.

## Limitations

- **Overwrite erasure is not guaranteed on every disk.** Overwriting in place does not guarantee physical erasure on SSDs with wear leveling or on copy-on-write file systems. Full-disk encryption at the host is the stronger control.
- **Backups are outside this module.** A backup taken before a purge still contains the fragments. Backup retention needs its own policy.
- **No per-request timeouts.** A slow vault call is bounded only by the caller's deadline. The assembler's `assemble_with_deadline` provides one for reconstruction.
- **No TLS listener for vault traffic.** Vaults are local files today, so there is no network path to protect. This needs revisiting if vaults move off the host.
- **Retries are immediate.** There is no backoff yet, so a flapping vault can see a burst of retries.

## Testing

```sh
cargo test -p tpt-shatter-vault-client
```

Tests cover breaker transitions (opening, half-open trials, and re-opening), logic errors passing through without tripping the breaker, encrypted file round trips across reopening, rejection of a wrong key, deletion, clearing of interrupted temporary files on open, retention purges, and purges that leave unauthenticated files in place.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
