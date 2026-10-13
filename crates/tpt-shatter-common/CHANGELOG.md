# Changelog

All notable changes to `tpt-shatter-common` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `VaultId` with the three vaults `A`, `B`, `C`, stable labels, and domain-separation tags. `VaultId::ALL` lists them in order.
- `ShardKey`, a 32-byte zeroized secret with redacted `Debug` and hex parsing (`from_hex`).
- `FragmentId`, a 32-byte opaque identifier with constant-time comparison (`ct_eq`) and hex parsing.
- `Record`, a flat field map with sorted field-name iteration.
- `ShatterSchema`, a versioned field-to-vault mapping, loadable from JSON with `from_json_str` and `load_json_file`, and validated on construction.
- `CapabilityToken`, `Scope`, and `Scopes` for token claims, with `check_live` and `check_scope` helpers. `DEFAULT_TOKEN_TTL_SECS` is 60.
- `RetentionPolicy` with `expires_at` and `is_expired`.
- `AuditChain`, `AuditRecord`, `AuditEvent`, and `AuditAction`: a keyed, hash-chained event log with `append`, `resume`, `verify_chain`, and `report`, which exports JSON.
- `AlertLog`: an append-only JSON-lines alert log that refuses forbidden field keys.
- `FragmentPayload`, a zeroized vault-and-bytes pair.
- `SecureZero` trait for in-place zeroing.
- `ShatterError`, the workspace-wide error type with coarse, non-revealing variants.

### Notes
- The crate is internal to the workspace and is not published (`publish = false`).
- Keys are supplied by callers. This crate does not generate or store them.
