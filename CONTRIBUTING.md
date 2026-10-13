# Contributing to tpt-shatter

Contributions are by issue only. Please open an issue to report a bug, ask a question, or propose a change. Pull requests and code patches are not accepted.

Read [DESIGN.md](DESIGN.md) first; it is the source of truth for the architecture. The project is licensed under the MIT License or the Apache License, Version 2.0, as in [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Issue guidelines

- Describe the problem or proposal, and the behavior you expected.
- Do not include payloads, fragments, FragmentIds, shard keys, tokens, or user identifiers in an issue. Use synthetic data.
- Report security vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

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

## Sensitive data rules

- Never log payloads, fragments, FragmentIds, or user identifiers.
- Types holding sensitive data must implement zeroization and must not derive `Clone` or a revealing `Debug`.
- `unsafe` code is denied workspace-wide and only allowed in explicitly audited modules.
