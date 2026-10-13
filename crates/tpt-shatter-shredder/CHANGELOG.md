# Changelog

All notable changes to `tpt-shatter-shredder` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Shredder` with `shred`, which validates against the schema, writes one fragment per vault in parallel, and compensates partial failures.
- `erase`, an idempotent GDPR erasure across all vaults with a read-back `verified` flag.
- `Shredder::reap` and `run_reaper` for retrying orphaned deletes, with an attempt limit and an abandoned count.
- `OrphanStore`, in memory or as a JSON-lines file, attached with `Shredder::with_orphan_log`.
- `Shredder::with_store`, for sharing one orphan queue between several shredders.
- `Shredder::pending_orphans` for monitoring the queue.
