# tpt-shatter — Project Checklist

Copyright holder: TPT Solutions. License: `MIT OR Apache-2.0`.
Rule: no linked dependency may be Apache-2.0-only (MIT, dual MIT/Apache, BSD, ISC, etc. are fine).

---

## Phase 0 — Decisions, Licensing & Upstream Verification
Resolve these before the implementation phases that depend on them.

### Licensing policy
- [x] Confirm license policy: linked Rust crates only; deploy-time tools (OPA, Distroless, Terraform) exempt (see DECISIONS.md)
- [x] Write allow-list of acceptable licenses (MIT, BSD-2/3, ISC, Unlicense, Zlib, MIT/Apache-2.0 dual, etc.) (`deny.toml`)
- [x] List spec items that are Apache-only and decide replacements (DECISIONS.md: axum -> hyper, tonic/prost -> HTTP/JSON, parquet/arrow dropped; OpenTelemetry deferred, `tracing` chosen, DECISIONS.md Observability)
- [ ] Audit licenses of planned deps: axum, tonic, tokio, hmac, sha2, rand, zeroize, serde, thiserror, prost (check each) — PARTIAL: checked with `cargo info` and `cargo deny`; `rand` not yet used
- [x] (Historical, keystone dropped) Verify `tpt-keystone-db` license is compatible (GitHub)
- [x] Verify `tpt-strata` and `tpt-strata-parquet` licenses are compatible (GitHub)
- [x] Verify Parquet-related transitive deps (arrow/parquet crates are Apache-only?) and decide whether `tpt-strata-parquet` can be used

### Upstream integration
- [x] Record GitHub URLs, commit/tag pins for tpt-keystone-db and tpt-strata
- [x] (Historical, keystone dropped) Review tpt-keystone-db Rust API / wire protocol; choose native API vs wire client
- [x] (Historical, keystone dropped) Confirm keystone supports SCRAM-SHA-256 + TLS as the spec assumes (supported but opt-in; deployment config must enable it)
- [-] (Superseded: keystone dropped.) Confirm keystone exposes a query log / audit hook the canary can tail; if not, file/implement the feature upstream — PARTIAL: audit log is table `_mirror_audit`, readable by polling; no stream; query text capture unverified (UPSTREAM.md)
- [ ] Review tpt-strata embedding API (in-process ingest, group by, sum) and its durability model — PARTIAL: `Table`/`QueryBuilder` found; group-by/sum names and durability not documented upstream (UPSTREAM.md); decided JSONL is the durable copy (DECISIONS.md)
- [x] Confirm tpt-strata never needs a separate server process

### Open gaps from spec section 10 (design decisions)
- [x] Gap 1: Disaster recovery plan (per-vault backups, derivation key escrow, restore drills, RPO/RTO) — decided in DECISIONS.md; runbook and drills pending (Phase 11)
- [x] Gap 2: Inter-vault consistency (saga/compensation pattern, orphan fragment reaper, write ordering) — decided; saga done, reaper pending (Phase 6)
- [x] Gap 3: GDPR deletion orchestrator design (delete by FragmentId across all vaults, verification, backup handling) — decided; orchestrator done
- [x] Gap 4: Schema evolution / re-shatter migration (e.g. adding a 4th fragment, versioned shatter schema) — decided; migration tool pending (Phase 11)
- [x] Gap 5: HMAC key provisioning and rotation (token key + FragmentId derivation key, bootstrap, secret source, split custody) — decided; provisioning pending (Phase 11)
- [x] Gap 6: Audit trail without payload logging (what proves legitimate access, hashed-only entries, tamper evidence) — decided; `AuditChain` built

### Core design decisions
- [x] Finalize shatter schema: which fields go to vault A (identity), B (demographic), C (financial) (DECISIONS.md, config-driven)
- [x] Finalize FragmentId derivation: keyed HMAC-SHA256 of ShardKey + vault label (domain separation per vault)
- [x] Define ShardKey format and entropy requirements (256-bit CSPRNG, 64 hex chars)
- [x] Define token format: fields, scopes/actions, TTL (default 60s), encoding, signature
- [x] Define token issuer service contract (upstream auth out of scope) (DECISIONS.md; endpoint pending in Phase 4)
- [x] Define canary record prefix scheme and how it stays secret (HMAC-derived prefix, DECISIONS.md)
- [ ] Define mTLS identity scheme between internal services — PARTIAL: scheme recorded in DECISIONS.md; TLS/mTLS now built on rustls + graviola (no exception needed); certificate issuance pending
- [ ] Define alarm response: key rotation propagation to gateway/issuer, security notification channel — PARTIAL: recorded in DECISIONS.md; propagation and channel not built
- [x] Define k-anonymity threshold, noise epsilon, bucketing rules for analytics (k=10, epsilon 1.0, DECISIONS.md)
- [ ] Add threat-model addenda for decisions above (update spec section 7) — PARTIAL: decisions recorded in DECISIONS.md; DESIGN.md section 7 not yet updated

---

## Phase 1 — Repository & Workspace Scaffolding
- [x] Initialize git repository
- [x] Create Cargo workspace root `Cargo.toml` (shared package metadata: `license = "MIT OR Apache-2.0"`, authors TPT Solutions)
- [x] Add `LICENSE-MIT` (TPT Solutions)
- [x] Add `LICENSE-APACHE`
- [x] Add `NOTICE` file
- [x] Add license section to `README.md`
- [x] Add SPDX headers convention (`MIT OR Apache-2.0`) and enforce it
- [x] Rename/move `spec.txt` -> `DESIGN.md` (markdown table reflow still pending, tracked separately)
- [x] Create `.gitignore`, `rust-toolchain.toml`, `rustfmt.toml`, clippy config
- [x] Scaffold 9 crates under `crates/`: common, token, gateway, shredder, assembler, emitter, canary, anonymize, vault-client
- [x] Scaffold directories: `vaults/vault-frag-{a,b,c}`, `insight-vault/`, `infrastructure/{terraform,k8s,policies}`, `tests/{integration,canary}`
- [x] Add `deny.toml` (cargo-deny) that rejects Apache-only licenses and bans unwanted crates
- [x] Add GitHub Actions CI: fmt, clippy, test, cargo-deny, cargo-audit
- [x] Add `CONTRIBUTING.md` stating contributions are dual-licensed MIT OR Apache-2.0
- [ ] Set up `cargo-deny` license check as a required CI gate
- [x] Add `SECURITY.md` (disclosure process)
- [ ] Add workspace-wide lint rules (partial: `unsafe` denied and `dbg!` denied; sensitive-type logging lint still pending)

---

## Phase 2 — `tpt-shatter-common`
- [x] `FragmentId` opaque type (no Display of raw value; redacted Debug)
- [x] `ShardKey` routing key type
- [x] `CapabilityToken` parsed struct
- [x] `ShatterError` unified enum (thiserror) with non-leaking messages
- [x] `SecureZero` trait + zeroize-based helpers
- [x] `Zeroizing`-wrapped sensitive record types; ensure no `Clone`/`Debug` leaks
- [x] Vault identifier enum / labels (A, B, C)
- [x] Shatter schema types (field -> vault mapping), versioned
- [x] Unit tests for all types
- [x] Docs + license headers

---

## Phase 3 — `tpt-shatter-anonymize`
- [x] `bucket()` categorical range bucketing
- [x] `pseudonymize()` one-way SHA-256 with static salt (done; salt provisioning and rotation decided in DECISIONS.md, rotation tooling pending)
- [x] `add_noise()` Laplace mechanism (differential privacy, configurable epsilon)
- [x] `check_k_anonymity()` small-cohort gate
- [x] `mask()` UI display masking
- [x] Property-based tests (determinism, bounds, no PII in output)
- [x] Statistical tests for Laplace noise distribution
- [x] Docs + license headers

---

## Phase 4 — `tpt-shatter-token`
- [x] 256-bit entropy token generation (CSPRNG)
- [x] HMAC-SHA256 signing and constant-time verification
- [x] Stateless validation (no session store)
- [x] TTL enforcement (default 60s) with bounded clock-skew tolerance
- [x] Bind token to ShardKey and action scopes
- [x] Signing key versioning + instant rotation (invalidate all active tokens)
- [x] Token issuer service/endpoint (called by host app after upstream auth) — built in `tpt-shatter-node` (`POST /v1/tokens`): bearer secrets stored as SHA-256, scope and TTL policy per caller, delete never issuable, issuance audited to a keyed chain before release (tested, and smoke-tested end to end over HTTP). Gaps: no caller field in audit events; caller auth is secrets only unless client_ca is set
- [x] Replay-resistance decision implemented (e.g. nonce/short TTL only) and documented
- [x] Unit tests: expiry, tamper, wrong scope, wrong shard, wrong key, rotated key
- [ ] Fuzz tests for token parser (partial: proptest stand-in in place; real cargo-fuzz targets still pending)
- [x] Docs + license headers

---

## Phase 5 — `tpt-shatter-vault-client` & Vaults
- [ ] Typed read/write ops per vault schema (A, B, C) — PARTIAL: generic per-vault ops done; schema-typed layer pending
- [x] Connection pooling — N/A: no network connections to vaults (`FileVault`)
- [x] Enforce single-vault queries only (no cross-vault joins at client level)
- [x] TLS + SCRAM-SHA-256 connection setup — N/A: keystone dropped; vaults are local `FileVault` directories (DECISIONS.md, "Vault storage")
- [ ] Timeouts, retries, circuit breaker per vault — PARTIAL: breaker and bounded retries done; per-request timeouts pending
- [x] Vault connection status reporting (for observability)
- [x] Delete-by-FragmentId operation (needed for GDPR)
- [x] Mock/in-memory vault implementation for tests
- [x] Internal vault store `FileVault` (replaces keystone): ChaCha20-Poly1305 per fragment with vault label and FragmentId as associated data, atomic writes, overwrite-then-remove erasure, temp-file cleanup on open (tested, including tamper, wrong key, and cross-vault copy)
- [ ] `FileVault` gaps — PARTIAL: no replication, no backups, overwrite erasure not guaranteed on SSD/CoW volumes (key destruction not wired), no key delivery
- [x] Node process `tpt-shatter-node` (new crate): JSON config with unknown fields rejected, keys from the environment, TLS required by default, one router with the canary observer, gateway over the assembler, reaper and canary-monitor threads (tested: record round trip, canary read rotates the token key; smoke-tested over HTTP)
- [x] Ingestion write path — `PUT /v1/records/{shard}` with a `Write`-scoped token: `Writer` in the gateway (rate limit, scope check, uniform errors, never echoes the record), a 64 KiB body limit, unknown fields refused as 400, and one shared orphan store so reaper and ingestion agree (tested at unit, HTTP, and node level)
- [ ] Node gaps — PARTIAL: keys from environment (no secret store), no container image or supervisor, one node per vault directory (no lock); the write path was tested in-process, not with a live HTTP write from a token minted outside the node
- [ ] `vaults/vault-frag-a` config: FileVault directory and sealing key (identity) — PARTIAL: `FileVault` built; per-vault config and key delivery pending
- [ ] `vaults/vault-frag-b` config: FileVault directory and sealing key (demographic) — PARTIAL: as above
- [ ] `vaults/vault-frag-c` config: FileVault directory and sealing key (financial/sensitive) — PARTIAL: as above
- [ ] Per-vault credentials and separate secrets; no shared creds — PARTIAL: each vault has its own sealing key by construction; key delivery pending
- [ ] Storage config: one volume per vault, no replication between vaults — PARTIAL: one directory per vault in `FileVault`; volume layout not built
- [ ] Per-vault automated backup config
- [x] Docs + license headers

---

## Phase 6 — `tpt-shatter-shredder`
- [ ] Configurable shatter schema loader (versioned) — PARTIAL: JSON loader done (`ShatterSchema::load_json_file` in common); shredder wiring and other formats pending
- [x] Split record into N fragments per schema
- [x] FragmentId derivation (keyed HMAC, per-vault domain separation), no mapping table
- [x] Parallel dispatch to vaults via vault-client
- [x] Saga/compensation on partial write failure (roll back orphan fragments)
- [x] Idempotent writes / retry safety
- [x] Securely zero original record after dispatch
- [ ] Internal gRPC (tonic) ingestion service with mTLS — PARTIAL: pending: needs tonic and mTLS
- [ ] Derivation key loading (RAM only, from provisioning mechanism) — PARTIAL: caller supplies key; RAM-only provisioning pending (Phase 11)
- [ ] Orphan fragment reaper (background) — PARTIAL: `Shredder::reap` with bounded retries and abandonment (tested); `run_reaper` runs passes on an interval until stopped (tested); orphan queue is durable via `Shredder::with_orphan_log` (atomic rewrite, restart test); attempt counts reset on restart; abandoned orphans cannot be located again (the queue holds FragmentIds, not ShardKeys); the abandonment alarm is a callback hook, with no notification channel yet and no deployed scheduler
- [x] Unit + integration tests with synthetic records
- [x] Docs + license headers

---

## Phase 7 — `tpt-shatter-assembler`
- [x] Derive FragmentIds from ShardKey
- [x] Parallel fetch from all vaults
- [x] Reconstruct record in RAM only
- [x] Pass record to emitter, return to gateway
- [ ] Zero all memory on completion and on every error path — PARTIAL: buffers are Zeroizing; memory-level verification pending
- [ ] `mlock` / `mlockall` usage with CAP_IPC_LOCK; fail closed if unavailable — PARTIAL: pending; needs Linux host
- [ ] Disable core dumps (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE`) — PARTIAL: pending; needs Linux host
- [ ] Per-request timeout; abort cleanly and zero on cancellation — PARTIAL: pending
- [x] Handle missing/partial fragments safely (no partial record returned)
- [ ] Internal gRPC (tonic) interface for the gateway, with mTLS — PARTIAL: pending: needs tonic and mTLS
- [ ] Statically linked build (musl) with no shell — PARTIAL: pending; needs musl toolchain
- [ ] Memory-safety tests (see Phase 13) — PARTIAL: pending (see Phase 13)
- [x] Docs + license headers

---

## Phase 8 — `tpt-shatter-emitter` & `insight-vault`
- [x] Apply anonymization transforms (bucket, pseudonymize, noise)
- [x] k-anonymity gate before emit
- [ ] Emit to embedded tpt-strata engine — PARTIAL: `EventSink` trait, `MemorySink`, and durable `JsonlSink` (fsynced, read-back) done; strata adapter pending upstream API confirmation
- [x] Signal assembler to zero record after emit
- [ ] `insight-vault/` setup: strata storage layout and schema for anonymized events — PARTIAL: pending
- [x] Decide embedded vs sidecar deployment for strata (embedded, DECISIONS.md)
- [x] Decide on tpt-strata-parquet bridge: dropped (Apache-only deps; banned in deny.toml)
- [ ] Sample aggregation queries (sum, group by) for BI access
- [ ] Analytics subnet access path for BI tools (emitter-only inbound)
- [ ] Tests: no raw PII present in strata output — PARTIAL: verified against MemorySink; re-run on strata
- [x] Docs + license headers

---

## Phase 9 — `tpt-shatter-gateway`
- [x] HTTP/JSON server — hyper 1 (MIT) in `crates/tpt-shatter-gateway/src/http.rs`; axum avoided because it pulls sync_wrapper (Apache-only). TLS is separate (below)
- [x] Capability token validation (HMAC, TTL, scope)
- [x] Rate limiting (per token hash / per source) — per token hash in `Gateway::read`; per source IP (digest of the peer address, port excluded) on `/v1/records` in `http.rs`, refused with 429 before the token check; tested. Not set by default: deployment must pass a `source_limiter`
- [ ] Route validated requests to the assembler (gRPC, mTLS) — PARTIAL: in-process RecordSource trait done; transport decided as HTTP/JSON, not gRPC (prost is Apache-only, see DECISIONS.md); assembler client and mTLS pending
- [x] Return responses; uniform error responses that leak nothing
- [x] Logs only token hashes and metadata
- [x] Key rotation signal receiver (from canary) with instant effect
- [x] Health/readiness endpoints — `/healthz` and `/readyz` in `http.rs`, tested
- [x] TLS termination config — `serve_tls` (TLS 1.3, optional mTLS) built on rustls 0.23 + rustls-graviola 0.2.1, tested with real handshakes (`tests/tls.rs`); cert issuance and rotation pending
- [ ] Verify the gateway has no network path to any vault — PARTIAL: gateway has no vault-client dependency; network isolation is infrastructure work
- [ ] Request size limits, timeouts, header hardening — PARTIAL: request-head size limit and per-request timeout done in `http.rs` (tested); body limits not needed for GET; no-store and nosniff headers set
- [x] Docs + license headers

---

## Phase 10 — `tpt-shatter-canary`
- [ ] Canary record generator (synthetic high-value records, realistic-looking) — PARTIAL: structured records, not yet realistic
- [x] Secret deterministic prefix scheme
- [x] Periodic injection into all vaults: `refresh_canaries` writes the current epoch through the shredder and erases the previous one, in that order, and is idempotent (tested); `monitor_loop` in `tpt-shatter-node/src/main.rs` calls it each `monitor_interval_secs`
- [x] Canary refresh/rotation schedule: `CanaryRotation` gives the current epoch's plan, `refresh_canaries` applies it (tested), `canary_period_secs` in node config (default 7 days), and `monitor_loop` runs it on a timer
- [-] Vault query-log tailer (per vault) — superseded: vaults are internal now, so detection runs in the router instead of tailing a database log
- [ ] Detect canary FragmentId in query logs — PARTIAL (renamed in scope: in-band, not query logs): `Router::with_observer` + `CanaryWatch` alarm on each observed read or delete of a canary FragmentId; writes and `*_maintenance` paths are not observed, so rotation and erasure do not alarm (tested). `CanaryMonitor::poll` runs the response and logs each alarm, and requeues on failure (tested). `monitor_loop` calls `poll` on a timer; direct file access on the host is not seen
- [x] Alarm: rotate HMAC signing key, invalidate all tokens: `AlarmResponder` in `tpt-shatter-node` rotates the node's token `Signer` (tested end to end: `a_canary_read_through_the_node_rotates_the_token_key`)
- [ ] Alarm: notify security (webhook/email/pager integration) — PARTIAL: `AlertLog` (append-only JSON-lines, fsynced, forbids value-bearing keys) is the channel; `Alarm::record` and `run_reaper` write to it (tested). Pager/SIEM tailing of the file and webhook delivery are not built
- [x] Alarm event logging (event only, never canary values)
- [x] Rate-limited alarm handling to avoid alert storms; manual re-arm procedure
- [ ] Management-subnet-only access to vaults and gateway
- [x] Docs + license headers

---

## Phase 11 — Cross-Cutting Capabilities
### GDPR / retention
- [x] Deletion orchestrator service (delete by FragmentId across all vaults)
- [x] Deletion verification and idempotency
- [ ] Backup handling for erased subjects (expiry or tombstone replay on restore)
- [x] Retention policy enforcement (TTL on fragments): `FileVault` stores each fragment's stored-at time under the AEAD (`nonce || stored_at || sealed`); `FileVault::purge_expired` erases expired files and leaves any that fail to authenticate (tested); the node runs it on `purge_interval_secs` and requires `retention_secs >= canary_period_secs`. Scope: existing fragment files from before this change are unreadable (no migration); purge is per fragment, so a record can lose some fragments before others, which the assembler reports as a failed read

### Audit trail
- [x] Define audit event schema (who/what/when via token hash and shard hash, no payload)
- [ ] Implement tamper-evident audit log (hash chain) — PARTIAL: keyed HMAC chain with verify/resume in common (in-memory); durable storage and export pending
- [ ] Compliance export/report tooling

### Disaster recovery
- [ ] Backup/restore runbook per vault
- [ ] Derivation key and token key escrow/recovery procedure
- [ ] Restore drill test

### Schema evolution
- [x] Schema version stored with fragments (4-byte header on every fragment; assembler refuses a mismatch, tested)
- [ ] Re-shatter migration tool (read via assembler, write via shredder, verify, retire old)

### Key provisioning
- [ ] Bootstrap mechanism for HMAC / derivation keys (RAM-only delivery)
- [ ] Rotation procedure and tooling
- [ ] Key custody split so no single person holds everything

### Observability
- [ ] Structured JSON logging (`tracing`), with redaction types so sensitive values cannot be logged
- [ ] Metrics: latency, vault connection status, error codes
- [ ] OTLP/OpenTelemetry export using MIT-compatible crates (replace Apache-only crates)
- [ ] Grafana dashboards and alerts
- [ ] Lint/test that blocks logging of payloads, fragments, FragmentIds, user identifiers

---

## Phase 12 — Infrastructure
### Terraform (cloud-agnostic)
- [ ] Network segments: DMZ, private (assembler/shredder), vault subnets (isolated), management, analytics
- [ ] Security groups / firewall rules per spec section 6.1 table
- [ ] Vault subnets isolated from each other
- [ ] Storage for vault backups (per-vault buckets/credentials)
- [ ] Secret management wiring

### Kubernetes
- [ ] Manifests for each service, distroless images
- [ ] Assembler: tmpfs root, no persistent volumes, swap disabled, `CAP_IPC_LOCK`, read-only root fs
- [ ] NetworkPolicies matching the isolation table
- [ ] Pod security: non-root, drop all caps (except required), seccomp
- [ ] mTLS between internal services (cert provisioning) — PARTIAL: mTLS listener built and tested (gateway `serve_tls` with client CA); provisioning and rotation pending
- [ ] Vault StatefulSets with separate namespaces/nodes
- [ ] Container build pipeline (static musl Rust binaries, no shell/curl)

### Policies
- [ ] OPA policies: admission rules (tmpfs, no hostPath, no privileged, image allow-list)
- [ ] OPA/network policies: cross-vault traffic denied
- [ ] Policy tests

---

## Phase 13 — Testing
- [ ] Unit tests for all 9 crates using synthetic data — PARTIAL: gateway has no implementation or tests yet
- [x] Integration: full pipeline (shred -> vaults -> assemble -> emit -> strata)
- [x] Integration: fragments land in the correct vault only
- [x] Integration: assembler reconstructs record exactly
- [ ] Integration: emitter writes to tpt-strata and output is anonymized — PARTIAL: checked against MemorySink; strata pending
- [x] Canary tests: inject, query, alarm fires, tokens revoked (alarm path and revocation are tested separately, not in one end-to-end test)
- [ ] Memory-safety tests: zeroize called; custom allocator asserts memory zeroed after drop — PARTIAL: `Record` is `ZeroizeOnDrop` (compile-time test); allocator-level check pending (needs unsafe, out of policy)
- [ ] Chaos: kill assembler mid-request, no partial data persists
- [x] Chaos: kill one vault, graceful degradation
- [x] Chaos: partial shred write, saga compensates
- [ ] Pen test: cross-vault query attempts
- [ ] Pen test: token replay, tamper, expiry
- [ ] Pen test: extract data from assembler disk image (expect nothing)
- [ ] Fuzzing for token parser and gRPC inputs
- [x] Log-scan test: no sensitive values in logs — `logs_and_alerts_never_contain_values_tokens_or_shard_keys` (node) checks every access-log line for reads and writes, successful and refused, plus the alert log after an alarm. Scope: the log lines as generated, not a live HTTP capture or stderr output
- [ ] Load/latency benchmarks for read path
- [x] CI runs all non-infrastructure tests

---

## Phase 14 — Documentation, Compliance & Release
- [x] README (overview, quick start, license)
- [ ] Update `DESIGN.md` with resolved gaps and final decisions — PARTIAL: section 12 (stack) updated, section 12a summarizes decisions and threat-model addenda; section 10 gap table not yet marked resolved
- [ ] Operations runbook (deploy, rotate keys, canary alarm response, DR) — PARTIAL: draft in `docs/RUNBOOK.md` grounded in the real APIs; deploy, key delivery, notification, and DR steps are marked GAP until built
- [ ] Compliance mapping notes: GDPR, PCI-DSS, HIPAA, SOC 2
- [ ] Security review of assembler and token crates
- [ ] Final dependency license audit (`cargo deny check`) and attribution notices — PARTIAL: `cargo deny check` passes on the current tree; attribution (NOTICE) for third-party crates not yet generated
- [x] Versioning/changelog (`CHANGELOG.md`)
- [ ] Release checklist and tagged `v1.0.0`
