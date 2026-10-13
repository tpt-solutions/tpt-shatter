# Changelog

All notable changes to `tpt-shatter-vault-client` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `VaultBackend` trait and `MemoryVault` in-memory backend.
- `FileVault`: ChaCha20-Poly1305 encrypted, one file per fragment, with atomic writes, overwrite-on-delete, and `purge_expired` retention.
- `Guarded` circuit breaker with `BreakerConfig` defaults (threshold 5, cooldown 30 s, 2 attempts) and `VaultStatus` snapshots.
- `Router`, which routes each call to exactly one vault, with observed (`get`, `delete`) and unobserved maintenance methods.
- `AccessObserver` hook for observing reads and deletes before they run.
- `derive_fragment_id` and `keyed_digest`: HMAC-SHA256 fragment addressing with per-vault domain tags.
- Fragment body codec: `encode_fields`, `decode_fields`, and a 4-byte schema version header.
