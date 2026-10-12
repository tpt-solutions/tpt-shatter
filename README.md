# tpt-shatter

`tpt-shatter` is a data security architecture that provides confidentiality and integrity
through **data fragmentation**, **ephemeral in-memory processing**, **strict network isolation**,
**capability-based access control**, **canary (honeytoken) detection**, and **anonymized analytics**.

> **Status:** design phase. The workspace is scaffolded; no crate is implemented yet.

- Architecture and rationale: [spec.txt](spec.txt)
- Implementation checklist: [todo.md](todo.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reporting: [SECURITY.md](SECURITY.md)

## Quick start

```sh
cargo build --workspace
cargo test --workspace
```

## License

Copyright (c) 2026 TPT Solutions.

Licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. See [NOTICE](NOTICE) for attribution details.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this work shall be dual licensed as above, without any additional terms or conditions.
