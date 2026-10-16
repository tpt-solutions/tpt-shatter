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
- [x] Review tpt-strata embedding API (in-process ingest, group by, sum) and its durability model — checked against the pinned source: `QueryBuilder::group_by` and `aggregate` (Sum, Count) exist; strata does no file or network I/O, so JSONL is the durable copy (UPSTREAM.md, DECISIONS.md)
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
- [x] Create `.gitignore`, `rust-toolchain.toml`, `rustfmt.toml`, clippy config
- [x] Scaffold 9 crates under `crates/`: common, token, gateway, shredder, assembler, emitter, canary, anonymize, vault-client
- [x] Scaffold directories: `vaults/vault-frag-{a,b,c}`, `insight-vault/`, `infrastructure/{terraform,k8s,policies}`, `tests/{integration,canary}`
- [x] Add `deny.toml` (cargo-deny) that rejects Apache-only licenses and bans unwanted crates
- [x] Add GitHub Actions CI: fmt, clippy, test, cargo-deny, cargo-audit
- [x] Add `CONTRIBUTING.md` (contributions by issue only; no pull requests accepted)
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
- [x] Token issuer service/endpoint (called by host app after upstream auth) — built in `tpt-shatter-node` (`POST /v1/tokens`): bearer secrets stored as SHA-256, scope and TTL policy per caller, delete never issuable, issuance audited to a keyed chain before release (tested, and smoke-tested end to end over HTTP). Gaps: caller auth is secrets only unless client_ca is set. Caller identity is recorded (token v2, keyed digest in the chain). Duplicate caller names are refused at startup (tested)
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
- [ ] Node gaps — PARTIAL: keys from `TPT_KEYS_DIR` (tmpfs, mode-checked) or environment (development), KEK tool built but not audited, and no tmpfs check; remote vault mode is tested, but its per-request TLS handshake is not measured; no container image or supervisor; one node per vault directory (no lock); the write path was tested in-process, not with a live HTTP write from a token minted outside the node
- [ ] `vaults/vault-frag-a` config: FileVault directory and sealing key (identity) — PARTIAL: `FileVault` built; per-vault config and key delivery pending
- [ ] `vaults/vault-frag-b` config: FileVault directory and sealing key (demographic) — PARTIAL: as above
- [ ] `vaults/vault-frag-c` config: FileVault directory and sealing key (financial/sensitive) — PARTIAL: as above
- [ ] Per-vault credentials and separate secrets; no shared creds — PARTIAL: each vault can run as its own service with its own key file, over mTLS (`tpt-shatter-vault-service`, tested on loopback, and a node round trip through three services). The node holds no vault key in that mode. Not deployed; OpenBao unwrap not built (DECISIONS.md, second round)
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
- [ ] Per-request timeout; abort cleanly and zero on cancellation — PARTIAL: the node read path uses `assemble_with_deadline` with a 3 s `READ_DEADLINE`, shorter than the 5 s HTTP timeout, so a stalled read returns `503` and frees its blocking thread. A vault call still running is not cancelled; it finishes in the background and its late body is dropped
- [x] Handle missing/partial fragments safely (no partial record returned)
- [ ] Internal gRPC (tonic) interface for the gateway, with mTLS — PARTIAL: HTTP/JSON over mTLS is built (`tpt-shatter-assembler-service`, client `RemoteAssembler`); gRPC was not adopted (see DECISIONS.md)
- [ ] Statically linked build (musl) with no shell — PARTIAL: pending; needs musl toolchain
- [ ] Memory-safety tests (see Phase 13) — PARTIAL: pending (see Phase 13)
- [x] Docs + license headers

---

## Phase 8 — `tpt-shatter-emitter` & `insight-vault`
- [x] Apply anonymization transforms (bucket, pseudonymize, noise)
- [x] k-anonymity gate before emit
- [x] Emit to embedded tpt-strata engine — `StrataSink` (`strata.rs`): durable timestamped JSONL first, then the in-memory strata view. Rebuilt from the log on open. `count_by` and `sum_by` are tested, including an empty view and a field no event holds. Node feed wired: accepted writes are anonymized at ingest, held, and emitted once the k-anonymity gate passes (`analytics.rs`, tested)
- [x] Analytics retention: events are purged from the log and the view after `retention_secs` (`purge_before`, tested; node purge tested with the same window as vault fragments). Decided in DECISIONS.md
- [x] Signal assembler to zero record after emit
- [ ] `insight-vault/` setup: strata storage layout and schema for anonymized events — PARTIAL: the feed writes `state_dir/analytics.jsonl` (timestamped, policy-approved fields only). `insight-vault/` is still an empty directory and is not used; deciding whether it should hold that file is part of deployment (Phase 12)
- [x] Decide embedded vs sidecar deployment for strata (embedded, DECISIONS.md)
- [x] Decide on tpt-strata-parquet bridge: dropped (Apache-only deps; banned in deny.toml)
- [x] Sample aggregation queries (sum, group by) for BI access — `tpt-shatter-node export-analytics` writes count or sum CSV per group, within the retention window, suppressing groups under k, with formula-injection guarding. Reads the log only, so it is safe while the node runs (tested, and smoke-tested through the binary). Scheduled exports (`analytics.exports`) rewrite CSV files in `export_dir` on an interval, atomically (tested). Delivery to a BI tool is not built (see DECISIONS.md, BI access)
- [ ] Analytics subnet access path for BI tools (emitter-only inbound)
- [x] Tests: no raw PII present in strata output — the log and both strata views (count and sum) are checked for raw name, card, and SSN values, and the bucketed year must appear (`the_log_and_the_strata_views_hold_no_raw_identifiers`)
- [x] Docs + license headers

---

## Phase 9 — `tpt-shatter-gateway`
- [x] HTTP/JSON server — hyper 1 (MIT) in `crates/tpt-shatter-gateway/src/http.rs`; axum avoided because it pulls sync_wrapper (Apache-only). TLS is separate (below)
- [x] Capability token validation (HMAC, TTL, scope)
- [x] Rate limiting (per token hash / per source) — per token hash in `Gateway::read`; per source IP (digest of the peer address, port excluded) on `/v1/records` in `http.rs`, refused with 429 before the token check; tested. Not set by default: deployment must pass a `source_limiter`
- [x] Route validated requests to the assembler (gRPC, mTLS) — DONE over HTTP/JSON, not gRPC (prost is Apache-only, see DECISIONS.md): `RemoteAssembler` (gateway) and `tpt-shatter-assembler-service` (mTLS, end-to-end tests). Canary alarm propagation to a split gateway is still open (DECISIONS.md, gateway service)
- [x] Return responses; uniform error responses that leak nothing
- [x] Logs only token hashes and metadata
- [x] Key rotation signal receiver (from canary) with instant effect — across processes: the node pushes the new key to each gateway's alarm listener over mTLS, and each gateway installs it only if newer (DECISIONS.md, canary alarm propagation). Not durable across restarts
- [x] Health/readiness endpoints — `/healthz` and `/readyz` in `http.rs`, tested
- [x] TLS termination config — `serve_tls` (TLS 1.3, optional mTLS) built on rustls 0.23 + rustls-graviola 0.2.1, tested with real handshakes (`tests/tls.rs`); cert issuance and rotation pending
- [ ] Verify the gateway has no network path to any vault — PARTIAL: code-level separation done, and the standalone `tpt-shatter-gateway` binary (`tpt-shatter-gateway-service`) has no vault, assembler, shredder, or canary crates in its normal dependency tree. The gateway no longer depends on canary, so its dependency tree has no vault-client, assembler, or shredder (`cargo tree -p tpt-shatter-gateway`). Network isolation is infrastructure work
- [ ] Request size limits, timeouts, header hardening — PARTIAL: request-head size limit and per-request timeout done in `http.rs` (tested); body limits not needed for GET; no-store and nosniff headers set
- [x] Docs + license headers

---

## Phase 10 — `tpt-shatter-canary`
- [ ] Canary record generator (synthetic high-value records, realistic-looking) — PARTIAL: values are shaped by field name (`canary::values`): Luhn-valid card numbers, dates, names, test-range emails and phones, opaque IDs otherwise. Shapes come from name keywords because the schema has no field types; a schema type field would replace that
- [x] Secret deterministic prefix scheme
- [x] Periodic injection into all vaults: `refresh_canaries` writes the current epoch through the shredder and erases the previous one, in that order, and is idempotent (tested); `monitor_loop` in `tpt-shatter-node/src/main.rs` calls it each `monitor_interval_secs`
- [x] Canary refresh/rotation schedule: `CanaryRotation` gives the current epoch's plan, `refresh_canaries` applies it (tested), `canary_period_secs` in node config (default 7 days), and `monitor_loop` runs it on a timer
- [-] Vault query-log tailer (per vault) — superseded: vaults are internal now, so detection runs in the router instead of tailing a database log
- [ ] Detect canary FragmentId in query logs — PARTIAL (renamed in scope: in-band, not query logs): `Router::with_observer` + `CanaryWatch` alarm on each observed read or delete of a canary FragmentId; writes and `*_maintenance` paths are not observed, so rotation and erasure do not alarm (tested). `CanaryMonitor::poll` runs the response and logs each alarm, and requeues on failure (tested). `monitor_loop` calls `poll` on a timer; direct file access on the host is not seen
- [x] Alarm: rotate HMAC signing key, invalidate all tokens: `AlarmResponder` in `tpt-shatter-node` rotates the node's token `Signer` (tested end to end: `a_canary_read_through_the_node_rotates_the_token_key`)
- [ ] Alarm: notify security (webhook/email/pager integration) — PARTIAL: `AlertLog` (append-only JSON-lines, fsynced, forbids value-bearing keys) is the channel; `Alarm::record` and `run_reaper` write to it (tested). Pager/SIEM tailing of the file and webhook delivery are not built
- [x] Canary detection in the assembler service — DONE, with gaps (DECISIONS.md, canary detection on the assembler): the assembler watches its own router using the node's canary ID list (no canary key on that host) and locks all reads on the first canary read; the lock clears on restart. The node pushes the list over mTLS (`canary_push`, DECISIONS.md, canary list transport); a fresh assembler host starts awaiting that push and refuses reads until it arrives. Gaps: the lock does not revoke tokens or reach the node (the gateway fails closed because reads stop); a stale list is logged (`canary_list_stale`), not locked
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
- [ ] Implement tamper-evident audit log (hash chain) — PARTIAL: keyed HMAC chain in common; durable, verified-on-open log (`AuditStore`, node) records issue, ingest, read, and alarm events. Gateway and writer record each authorized operation before it runs, and fail closed if the append fails (tested). Alarms record the vault only, with zero digests. Erasure is recorded: `Node::erase_subject` writes an erasure event (shard digest only) before it deletes, and fails closed if the record cannot be written (tested). It has no HTTP or CLI entry point, by design, so erasure stays an operator-side call
- [ ] Compliance export/report tooling — PARTIAL: `audit::report` and `AuditReport::to_json` summarize a verified chain (counts, bounds, head MAC, no digests); `tpt-shatter-node export-audit <config.json>` prints the summary (tested). Scheduled export not built

### Disaster recovery
- [ ] Backup/restore runbook per vault
- [ ] Derivation key and token key escrow/recovery procedure
- [ ] Restore drill test

### Schema evolution
- [x] Schema version stored with fragments (4-byte header on every fragment; assembler refuses a mismatch, tested)
- [ ] Re-shatter migration tool (read via assembler, write via shredder, verify, retire old) — PARTIAL: `migrate_shard` (assembler crate) reads each fragment under its own version, writes without the shredder's compensating delete, verifies through the assembler, and resumes after a failed write. Old fragments are retired by overwrite. No batch driver or CLI; field moves are supported, field removal is refused

### Key provisioning
- [ ] Bootstrap mechanism for HMAC / derivation keys (RAM-only delivery) — PARTIAL: `tpt-shatter-kek` seals the keys under a KEK and unseals them into `TPT_KEYS_DIR` at boot, needing two custodians. Not audited; no check that the target is a tmpfs. Earlier note: the node reads keys from `TPT_KEYS_DIR`, a tmpfs directory that refuses group- or other-readable files (tested on Unix). The KMS unwrap that fills it is not built (DECISIONS.md, end)
- [ ] Rotation procedure and tooling
- [ ] Key custody split so no single person holds everything — PARTIAL: 2-of-3 Shamir over the KEK, built in `tpt-shatter-kek` (`blahaj`, MIT). It covers every node key, not only the derivation and audit keys. Not audited

### Observability
- [x] Structured JSON logging (`tracing`), with redaction types so sensitive values cannot be logged — the node binary logs one JSON object per line to stderr via `init_logging`; all log calls are `tracing` events with counts, codes, and hashes. Redaction: the core types (`ShardKey`, `FragmentId`, `Record`, `CapabilityToken`, `FragmentPayload`) print `Debug` without their values
- [x] Metrics: latency, vault connection status, error codes — Prometheus text at `/metrics` on the optional `metrics_listen` listener (`metrics.rs`, tested over real HTTP). Counts requests by status and gateway code, canary alarms, analytics emitted, fragments purged, a read-assembly latency histogram, and per-vault breaker state and failures read at scrape time. Labels are fixed vocabulary only. Put the listener on the management network. Not built: an OTLP exporter (see DECISIONS.md)
- [x] OTLP/OpenTelemetry export — decided: an OpenTelemetry Collector beside each node reads stdout logs and scrapes `/metrics` (DECISIONS.md). Deployment of the Collector is Phase 12 work. In-process exporter deferred unless a deployment cannot run a sidecar
- [ ] Grafana dashboards and alerts
- [ ] Lint/test that blocks logging of payloads, fragments, FragmentIds, user identifiers — PARTIAL: a test (`logs_and_alerts_never_contain_values_tokens_or_shard_keys`) runs the access-log lines and alert log through the same JSON subscriber the binary installs and checks for values, tokens, and shard keys. It covers the lines the HTTP layer passes to the sink, not every log call, and there is no static lint yet

---

## Phase 12 — Infrastructure
### Terraform (cloud-agnostic)
- [ ] Network segments: DMZ, private (assembler/shredder), vault subnets (isolated), management, analytics — NOT STARTED: Terraform resources are provider-specific, so this needs a target cloud. Segment inputs are in `infrastructure/README.md`
- [ ] Security groups / firewall rules per spec section 6.1 table — NOT STARTED (the in-cluster equivalent is in `infrastructure/k8s/network-policies.yaml`)
- [ ] Vault subnets isolated from each other — PARTIAL: isolated by NetworkPolicy in `infrastructure/k8s`; no network-level isolation yet
- [ ] Storage for vault backups (per-vault buckets/credentials) — NOT STARTED
- [ ] Secret management wiring — NOT STARTED

### Kubernetes (`infrastructure/k8s/`, applied as plain manifests; not run on a cluster)
- [ ] Manifests for each service, distroless images — PARTIAL: node and vault workloads written; image digests are placeholders and no distroless build exists yet
- [ ] Assembler: tmpfs root, no persistent volumes, swap disabled, `CAP_IPC_LOCK`, read-only root fs — PARTIAL: read-only root fs, memory-backed keys and scratch volumes, dropped caps. One PVC (`tpt-node-state`) is kept for node state, against spec 6.2; swap and `CAP_IPC_LOCK` not set (decision needed, see `infrastructure/README.md` gap 2)
- [x] NetworkPolicies matching the isolation table — PARTIAL-DONE: default-deny per namespace; vault accepts node only and has no egress. Gateway-in-DMZ separation is not possible while the node is one process (gap 1). Needs an enforcing CNI to take effect
- [ ] Pod security: non-root, drop all caps (except required), seccomp — PARTIAL: all set in the manifests and checked by OPA; not verified on a cluster
- [ ] mTLS between internal services (cert provisioning) — PARTIAL: mTLS listener built and tested; the manifests reference the Secrets, which nothing creates yet
- [x] Vault StatefulSets with separate namespaces/nodes — PARTIAL-DONE: one StatefulSet per vault namespace, each with its own volume. Node placement is not set
- [ ] Container build pipeline (static musl Rust binaries, no shell/curl)

### Policies (`infrastructure/policies/`)
- [x] OPA policies: admission rules (tmpfs, no hostPath, no privileged, image allow-list) — PARTIAL-DONE: rules written; the image allow-list is a placeholder default; tested with `opa test` (16/16). Not run as a live admission webhook
- [ ] OPA/network policies: cross-vault traffic denied — PARTIAL: each NetworkPolicy is checked as it arrives. Cannot prove a default-deny exists in each vault namespace without cluster-wide data (Gatekeeper sync)
- [x] Policy tests — 16 `opa test` cases pass, and the shipped manifests pass the rules

---

## Phase 13 — Testing
- [ ] Unit tests for all 9 crates using synthetic data — PARTIAL: every workspace crate has tests now (274 pass); per-crate coverage has not been audited
- [x] Integration: full pipeline (shred -> vaults -> assemble -> emit -> strata)
- [x] Integration: fragments land in the correct vault only
- [x] Integration: assembler reconstructs record exactly
- [ ] Integration: emitter writes to tpt-strata and output is anonymized — PARTIAL: checked against MemorySink; strata pending
- [x] Canary tests: inject, query, alarm fires, tokens revoked (alarm path and revocation are tested separately, not in one end-to-end test)
- [ ] Memory-safety tests: zeroize called; custom allocator asserts memory zeroed after drop — PARTIAL: `Record` is `ZeroizeOnDrop` (compile-time test); allocator-level check pending (needs unsafe, out of policy)
- [x] Chaos: kill assembler mid-request, no partial data persists — simulated: a read abandoned at its deadline returns no record, removes no fragment, and a later read succeeds (`an_abandoned_read_leaves_no_partial_state_and_a_later_read_succeeds`). Not a process kill
- [x] Chaos: kill one vault, graceful degradation
- [x] Chaos: partial shred write, saga compensates
- [x] Pen test: cross-vault query attempts — a vault B fragment copied over a vault A file reads nothing (`a_fragment_copied_into_another_vault_reads_nothing`, node level). Attacks through the query API are not separately tested; the router has no cross-vault path to test
- [x] Pen test: token replay, tamper, expiry — node-level tests through `Gateway::read`, not HTTP. Replay is accepted within the TTL and refused after it, by decision (DECISIONS.md); tampered signatures and shard-swapped tokens read nothing
- [ ] Pen test: extract data from assembler disk image (expect nothing)
- [ ] Fuzzing for token parser and gRPC inputs
- [x] Log-scan test: no sensitive values in logs — `logs_and_alerts_never_contain_values_tokens_or_shard_keys` (node) checks every access-log line for reads and writes, successful and refused, plus the alert log after an alarm. Scope: the log lines as generated, not a live HTTP capture or stderr output
- [ ] Load/latency benchmarks for read path — PARTIAL: in-process latency measurement (`read_path_latency`, ignored by default; p50 about 0.4 ms on file vaults). No load test, no concurrency, no HTTP path
- [x] CI runs all non-infrastructure tests

---

## Phase 14 — Documentation, Compliance & Release
- [x] README (overview, quick start, license)
- [ ] Update `DESIGN.md` with resolved gaps and final decisions — PARTIAL: section 12 (stack) updated, section 12a summarizes decisions and threat-model addenda; section 10 gap table not yet marked resolved
- [ ] Operations runbook (deploy, rotate keys, canary alarm response, DR) — PARTIAL: draft in `docs/RUNBOOK.md` grounded in the real APIs; deploy, key delivery, notification, and DR steps are marked GAP until built
- [x] Compliance mapping notes: GDPR, PCI-DSS, HIPAA, SOC 2 — `docs/COMPLIANCE.md` maps each control to its status and lists the open gaps. Not legal advice; the spec's section 11 overstated several claims, which the file corrects
- [ ] Security review of assembler and token crates — PARTIAL: one review pass done (docs/SECURITY_REVIEW.md). Fixed the stalled-vault thread growth with a per-vault in-flight cap. Open low-severity items are listed there. Not an independent audit, and fuzzing is pending
- [ ] Final dependency license audit (`cargo deny check`) and attribution notices — PARTIAL: `cargo deny check` passes on the current tree; `docs/THIRD_PARTY_NOTICES.md` lists the license of every linked crate (generated from cargo metadata). License texts and Apache-2.0 NOTICE files are not yet bundled; that step is manual
- [x] Versioning/changelog (`CHANGELOG.md`)
- [ ] Release checklist and tagged `v1.0.0` — PARTIAL: checklist in `docs/RELEASE.md`. Tag not created; that is the release owner's call
