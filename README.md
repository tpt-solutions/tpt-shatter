# tpt-shatter

`tpt-shatter` is a data security architecture that provides confidentiality and integrity
through **data fragmentation**, **ephemeral in-memory processing**, **strict network isolation**,
**capability-based access control**, **canary (honeytoken) detection**, and **anonymized analytics**.

> **Status:** early implementation. Every crate has a working implementation with tests. Known gaps are listed in each crate's README and in the checklist.

- Architecture and rationale: [DESIGN.md](DESIGN.md)
- Implementation checklist: [todo.md](todo.md)
- Decisions: [DECISIONS.md](DECISIONS.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reporting: [SECURITY.md](SECURITY.md)

## Crates

| Crate | Role | Docs |
| --- | --- | --- |
| [tpt-shatter-common](crates/tpt-shatter-common/) | Shared types, errors, schema, audit chain | [README](crates/tpt-shatter-common/README.md) · [CHANGELOG](crates/tpt-shatter-common/CHANGELOG.md) |
| [tpt-shatter-anonymize](crates/tpt-shatter-anonymize/) | Bucketing, pseudonyms, Laplace noise, k-anonymity | [README](crates/tpt-shatter-anonymize/README.md) · [CHANGELOG](crates/tpt-shatter-anonymize/CHANGELOG.md) |
| [tpt-shatter-token](crates/tpt-shatter-token/) | Capability tokens | [README](crates/tpt-shatter-token/README.md) · [CHANGELOG](crates/tpt-shatter-token/CHANGELOG.md) |
| [tpt-shatter-vault-client](crates/tpt-shatter-vault-client/) | Vault router, circuit breakers, encrypted file vault | [README](crates/tpt-shatter-vault-client/README.md) · [CHANGELOG](crates/tpt-shatter-vault-client/CHANGELOG.md) |
| [tpt-shatter-shredder](crates/tpt-shatter-shredder/) | Fragmentation, erasure, orphan reaper | [README](crates/tpt-shatter-shredder/README.md) · [CHANGELOG](crates/tpt-shatter-shredder/CHANGELOG.md) |
| [tpt-shatter-assembler](crates/tpt-shatter-assembler/) | Reconstruction, schema migration | [README](crates/tpt-shatter-assembler/README.md) · [CHANGELOG](crates/tpt-shatter-assembler/CHANGELOG.md) |
| [tpt-shatter-canary](crates/tpt-shatter-canary/) | Canary records, detection, alarm response | [README](crates/tpt-shatter-canary/README.md) · [CHANGELOG](crates/tpt-shatter-canary/CHANGELOG.md) |
| [tpt-shatter-emitter](crates/tpt-shatter-emitter/) | Anonymized output, k-anonymity gate, sinks | [README](crates/tpt-shatter-emitter/README.md) · [CHANGELOG](crates/tpt-shatter-emitter/CHANGELOG.md) |
| [tpt-shatter-gateway](crates/tpt-shatter-gateway/) | Token-checked HTTP and TLS read/write gateway | [README](crates/tpt-shatter-gateway/README.md) · [CHANGELOG](crates/tpt-shatter-gateway/CHANGELOG.md) |
| [tpt-shatter-node](crates/tpt-shatter-node/) | The node process and token issuer | [README](crates/tpt-shatter-node/README.md) · [CHANGELOG](crates/tpt-shatter-node/CHANGELOG.md) |

Each crate's README has its examples. Run any of them with `cargo run -p <crate> --example <name>`.

## Quick start

```sh
cargo build --workspace
cargo test --workspace
cargo run -p tpt-shatter-node --example in_process_node
```

## License

Copyright (c) 2026 TPT Solutions.

Licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. See [NOTICE](NOTICE) for attribution details.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this work shall be dual licensed as above, without any additional terms or conditions.
