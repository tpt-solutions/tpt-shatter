# Changelog

All notable changes to `tpt-shatter-emitter` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Policy` and `Transform` (`Drop`, `Mask`, `Bucket`, `Pseudonymize`, `Noise`), with validation of salt, `k`, bucket width, and quasi-identifier rules.
- `Emitter::emit`, which transforms a whole batch, applies the k-anonymity gate to it, and emits only when the gate passes.
- `EventSink` trait with `MemorySink` and `JsonlSink` (append-only JSON lines, with `read_all`).
- `StrataSink`: a durable JSON-lines log with an in-memory tpt-strata view, grouped `count_by` and `sum_by` aggregates, and rebuild-on-open.
- Tests for the absence of raw identifiers in output, the batch-wide k gate, policy validation, sink round trips, and aggregate rules.
