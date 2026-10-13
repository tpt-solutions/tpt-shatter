# Changelog

All notable changes to `tpt-shatter-assembler` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Assembler::assemble`, which fetches all three fragments in parallel and rebuilds the record, failing closed on any gap.
- `assemble_with_deadline`, which bounds reconstruction by a deadline and reports the first vault still outstanding.
- `migrate_shard`, which rewrites one shard from one schema version to another in place, reading each fragment under its own version header and tolerating half-migrated shards.
- End-to-end pipeline tests covering shred, assemble, emit, canary detection, and erasure.

### Not yet implemented
- Memory locking and core-dump hardening (`mlock`, `RLIMIT_CORE`).
- The internal gRPC interface with mTLS.
- The statically linked musl build.
