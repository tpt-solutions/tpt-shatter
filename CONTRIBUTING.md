# Contributing to tpt-shatter

Thanks for helping. Please read [DESIGN.md](DESIGN.md) first; it is the source of truth for the architecture.

## Licensing of contributions

Unless you state otherwise, any contribution you submit is dual-licensed under
the MIT License and the Apache License, Version 2.0, as in [LICENSE-MIT](LICENSE-MIT)
and [LICENSE-APACHE](LICENSE-APACHE), without any additional terms or conditions.

## Dependency policy

- Every new dependency must be MIT-compatible (MIT, dual `MIT OR Apache-2.0`, BSD, ISC, Unlicense, Zlib, Unicode-3.0).
- Apache-2.0-only dependencies are rejected by `cargo deny check` in CI.
- Deploy-time tools (OPA, Distroless, Terraform) are exempt from this rule.

## SPDX headers

Every Rust source file starts with:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions
```

CI fails if a `.rs` file is missing this header.

## Before opening a pull request

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## Sensitive data rules

- Never log payloads, fragments, FragmentIds, or user identifiers.
- Types holding sensitive data must implement zeroization and must not derive `Clone` or a revealing `Debug`.
- `unsafe` code is denied workspace-wide and only allowed in explicitly audited modules.
