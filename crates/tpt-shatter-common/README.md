# tpt-shatter-common

Shared vocabulary for tpt-shatter: the types, errors, schema format, audit chain, and alert log that every other crate in the workspace depends on.

This crate contains no business logic. It defines the words the rest of the system uses, and it defines the rules those words follow, such as which values may be printed and which may be copied.

> **Status:** implemented and tested. Not published to crates.io (`publish = false`); consumed by path from this workspace.

## Contents

- [What it provides](#what-it-provides)
- [Where it fits](#where-it-fits)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `ShatterError` | The one error type used across the workspace. Variants are coarse on purpose (for example `InvalidToken`, `Unauthorized`, `VaultUnavailable`) so that callers do not learn internal detail. |
| `VaultId` | The three vaults (`A`, `B`, `C`) with stable labels and domain-separation tags used in key derivation. `VaultId::ALL` lists them in order. |
| `ShardKey` | The 32-byte secret that names one record. Zeroized on drop. `Debug` prints `ShardKey(<redacted>)`. Parsed from 64 hex characters with `from_hex`. |
| `FragmentId` | The 32-byte opaque identifier for one fragment in one vault. Derived from the shard key, so it reveals nothing without the derivation key. |
| `Record` | A flat map from field name to string value. The unit that is shredded into fragments and reassembled. |
| `ShatterSchema` | Maps each field to exactly one vault, with a version number. Loaded from JSON with `from_json_str` or `load_json_file`, and validated on load. |
| `CapabilityToken`, `Scope`, `Scopes` | The claims carried by a token: a random ID, the granted scopes (`Read`, `Write`, `Delete`), the issue time, the lifetime, and the bound shard. |
| `RetentionPolicy` | A maximum age for stored fragments, with `expires_at` and `is_expired` helpers. |
| `AuditChain`, `AuditRecord`, `AuditEvent`, `AuditAction` | A keyed, hash-chained log. Each entry's MAC covers the previous one, so editing, reordering, or dropping an entry breaks verification. `verify_chain` checks it and `report` summarizes it as JSON. |
| `AlertLog` | An append-only JSON-lines log for security alerts. Refuses any field whose key is on the forbidden list, so raw identifiers cannot be written to it by accident. |
| `FragmentPayload` | A vault ID paired with the bytes destined for it, zeroized on drop. |
| `SecureZero` | Trait with a `secure_zero` method, implemented for arrays and strings, for overwriting sensitive values in place. |

## Where it fits

Every other crate depends on this one. Nothing here depends on another tpt-shatter crate.

```text
tpt-shatter-common
    ├── tpt-shatter-anonymize
    ├── tpt-shatter-token
    ├── tpt-shatter-vault-client ── tpt-shatter-shredder ── tpt-shatter-canary
    ├── tpt-shatter-assembler
    ├── tpt-shatter-emitter
    ├── tpt-shatter-gateway
    └── tpt-shatter-node
```

## Installation

This workspace is not published. Depend on the crate by path:

```toml
[dependencies]
tpt-shatter-common = { path = "../tpt-shatter-common" }
```

## Quick start

```rust
use tpt_shatter_common::{Record, ShardKey, ShatterSchema, VaultId};

let schema = ShatterSchema::new(
    1,
    [
        ("name", VaultId::A),
        ("birth_year", VaultId::B),
        ("card_number", VaultId::C),
    ],
)?;

let mut record = Record::new();
record.insert("name", "Synthetic Person");

let shard = ShardKey::from_bytes([0x42; 32]);
println!("{} fields, shard key {:?}", record.len(), shard); // prints ShardKey(<redacted>)
```

Schemas can also come from a file. A malformed file is rejected with `InvalidSchema`:

```rust
let schema = ShatterSchema::from_json_str(r#"{
    "version": 1,
    "fields": { "name": "A", "birth_year": "B", "card_number": "C" }
}"#)?;
```

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`schema_and_audit`](examples/schema_and_audit.rs) | Loading a schema, building a record and shard key, round-tripping a fragment ID, and building, verifying, and reporting an audit chain. | `cargo run -p tpt-shatter-common --example schema_and_audit` |

## Security properties

- **Redacted `Debug`.** `ShardKey` never prints its bytes. Debug output for sensitive values is redacted by design.
- **Zeroization.** Keys and payloads are zeroized when dropped, so copies do not linger in memory longer than needed.
- **Fail-closed schema validation.** A schema with version `0`, an empty field set, an invalid or duplicate field name, or an unknown vault label is rejected before anything uses it.
- **Tamper-evident audit.** The chain is keyed. Without the chain key, a forged or re-ordered history fails `verify_chain`.
- **No values in alerts.** `AlertLog::append` rejects forbidden keys, so the log can only hold what the caller meant to record.

## Limitations

- The audit chain proves an ordering of events, not who performed them. The caller's identity is recorded elsewhere (see the node's access log).
- `AlertLog` checks for forbidden keys by name. It cannot detect a sensitive value placed under an innocent key, so callers must choose their keys carefully.
- This crate does not generate keys. Callers supply them, and key provisioning is handled outside the workspace's current code.

## Testing

```sh
cargo test -p tpt-shatter-common
cargo run -p tpt-shatter-common --example schema_and_audit
```

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
