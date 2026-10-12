# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Workspace scaffolding: nine crates, CI (fmt, clippy, test, SPDX headers, cargo-deny, cargo-audit), and licensing (`MIT OR Apache-2.0`).
- `tpt-shatter-common`: core types (`FragmentId`, `ShardKey`, `CapabilityToken`, `ShatterError`, `VaultId`), zeroization helpers, and the versioned `ShatterSchema`.
- `ShatterSchema::from_json_str` and `ShatterSchema::load_json_file` for loading schemas from JSON.
- `tpt-shatter-anonymize`: bucketing, pseudonymization, Laplace noise, k-anonymity gate, and display masking.
- `tpt-shatter-token`: HMAC-SHA256 capability tokens with TTL, scope binding, and key rotation.

### Changed
- The architecture document is now `DESIGN.md` (previously `spec.txt`).
