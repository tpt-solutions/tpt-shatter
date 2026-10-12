# tpt-shatter — Project Checklist

Copyright holder: TPT Solutions. License: `MIT OR Apache-2.0`.
Rule: no linked dependency may be Apache-2.0-only (MIT, dual MIT/Apache, BSD, ISC, etc. are fine).

---

## Phase 0 — Decisions, Licensing & Upstream Verification
Resolve these before the implementation phases that depend on them.

### Licensing policy
- [ ] Confirm license policy: linked Rust crates only; deploy-time tools (OPA, Distroless, Terraform) exempt
- [ ] Write allow-list of acceptable licenses (MIT, BSD-2/3, ISC, Unlicense, Zlib, MIT/Apache-2.0 dual, etc.)
- [ ] List spec items that are Apache-only and decide replacements (OpenTelemetry Rust crates -> MIT alternative, e.g. `tracing` + JSON logs + OTLP exporter alternative)
- [ ] Audit licenses of planned deps: axum, tonic, tokio, hmac, sha2, rand, zeroize, serde, thiserror, prost (check each)
- [x] Verify `tpt-keystone-db` license is compatible (GitHub)
- [x] Verify `tpt-strata` and `tpt-strata-parquet` licenses are compatible (GitHub)
- [x] Verify Parquet-related transitive deps (arrow/parquet crates are Apache-only?) and decide whether `tpt-strata-parquet` can be used

### Upstream integration
- [x] Record GitHub URLs, commit/tag pins for tpt-keystone-db and tpt-strata
- [x] Review tpt-keystone-db Rust API / wire protocol; choose native API vs wire client
- [x] Confirm keystone supports SCRAM-SHA-256 + TLS as the spec assumes (supported but opt-in; deployment config must enable it)
- [ ] Confirm keystone exposes a query log / audit hook the canary can tail; if not, file/implement the feature upstream (open: audit log exists, tailability not verified)
- [ ] Review tpt-strata embedding API (in-process ingest, group by, sum) and its durability model (open: API and durability not yet reviewed)
- [x] Confirm tpt-strata never needs a separate server process

### Open gaps from spec section 10 (design decisions)
- [ ] Gap 1: Disaster recovery plan (per-vault backups, derivation key escrow, restore drills, RPO/RTO)
- [ ] Gap 2: Inter-vault consistency (saga/compensation pattern, orphan fragment reaper, write ordering)
- [ ] Gap 3: GDPR deletion orchestrator design (delete by FragmentId across all vaults, verification, backup handling)
- [ ] Gap 4: Schema evolution / re-shatter migration (e.g. adding a 4th fragment, versioned shatter schema)
- [ ] Gap 5: HMAC key provisioning and rotation (token key + FragmentId derivation key, bootstrap, secret source, split custody)
- [ ] Gap 6: Audit trail without payload logging (what proves legitimate access, hashed-only entries, tamper evidence)

### Core design decisions
- [ ] Finalize shatter schema: which fields go to vault A (identity), B (demographic), C (financial)
- [ ] Finalize FragmentId derivation: keyed HMAC-SHA256 of ShardKey + vault label (domain separation per vault)
- [ ] Define ShardKey format and entropy requirements
- [ ] Define token format: fields, scopes/actions, TTL (default 60s), encoding, signature
- [ ] Define token issuer service contract (upstream auth out of scope)
- [ ] Define canary record prefix scheme and how it stays secret
- [ ] Define mTLS identity scheme between internal services
- [ ] Define alarm response: key rotation propagation to gateway/issuer, security notification channel
- [ ] Define k-anonymity threshold, noise epsilon, bucketing rules for analytics
- [ ] Add threat-model addenda for decisions above (update spec section 7)

---

## Phase 1 — Repository & Workspace Scaffolding
- [x] Initialize git repository
- [x] Create Cargo workspace root `Cargo.toml` (shared package metadata: `license = "MIT OR Apache-2.0"`, authors TPT Solutions)
- [x] Add `LICENSE-MIT` (TPT Solutions)
- [x] Add `LICENSE-APACHE`
- [x] Add `NOTICE` file
- [x] Add license section to `README.md`
- [x] Add SPDX headers convention (`MIT OR Apache-2.0`) and enforce it
- [ ] Rename/move `spec.txt` -> `DESIGN.md` (renamed; markdown table reflow still pending)
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
- [x] `pseudonymize()` one-way SHA-256 with static salt (done; salt provisioning and rotation notes still pending)
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
- [ ] Token issuer service/endpoint (called by host app after upstream auth)
- [x] Replay-resistance decision implemented (e.g. nonce/short TTL only) and documented
- [x] Unit tests: expiry, tamper, wrong scope, wrong shard, wrong key, rotated key
- [ ] Fuzz tests for token parser (partial: proptest stand-in in place; real cargo-fuzz targets still pending)
- [x] Docs + license headers

---

## Phase 5 — `tpt-shatter-vault-client` & Vaults
- [ ] Typed read/write ops per vault schema (A, B, C) — PARTIAL: generic per-vault ops done; schema-typed layer pending
- [ ] Connection pooling — PARTIAL: pending real backend
- [x] Enforce single-vault queries only (no cross-vault joins at client level)
- [ ] TLS + SCRAM-SHA-256 connection setup — PARTIAL: pending real tpt-keystone-db backend
- [ ] Timeouts, retries, circuit breaker per vault — PARTIAL: breaker and bounded retries done; per-request timeouts pending
- [x] Vault connection status reporting (for observability)
- [x] Delete-by-FragmentId operation (needed for GDPR)
- [x] Mock/in-memory vault implementation for tests
- [ ] `vaults/vault-frag-a` config: tpt-keystone-db instance (identity)
- [ ] `vaults/vault-frag-b` config: tpt-keystone-db instance (demographic)
- [ ] `vaults/vault-frag-c` config: tpt-keystone-db instance (financial/sensitive)
- [ ] Per-vault credentials and separate secrets; no shared creds
- [ ] Storage config (S3/local-fs + NVMe cache-aside), no replication between vaults
- [ ] Per-vault automated backup config
- [x] Docs + license headers

---

## Phase 6 — `tpt-shatter-shredder`
- [ ] Configurable shatter schema loader (versioned) — PARTIAL: serde deserialization exists; file loader pending
- [x] Split record into N fragments per schema
- [x] FragmentId derivation (keyed HMAC, per-vault domain separation), no mapping table
- [x] Parallel dispatch to vaults via vault-client
- [x] Saga/compensation on partial write failure (roll back orphan fragments)
- [x] Idempotent writes / retry safety
- [x] Securely zero original record after dispatch
- [ ] Internal gRPC (tonic) ingestion service with mTLS — PARTIAL: pending: needs tonic and mTLS
- [ ] Derivation key loading (RAM only, from provisioning mechanism) — PARTIAL: caller supplies key; RAM-only provisioning pending (Phase 11)
- [ ] Orphan fragment reaper (background) — PARTIAL: pending; compensation failures are left for it
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
- [ ] Emit to embedded tpt-strata engine — PARTIAL: sink trait only; strata adapter pending API review
- [x] Signal assembler to zero record after emit
- [ ] `insight-vault/` setup: strata storage layout and schema for anonymized events — PARTIAL: pending
- [ ] Decide embedded vs sidecar deployment for strata
- [x] Decide on tpt-strata-parquet bridge: dropped (Apache-only deps; banned in deny.toml)
- [ ] Sample aggregation queries (sum, group by) for BI access
- [ ] Analytics subnet access path for BI tools (emitter-only inbound)
- [ ] Tests: no raw PII present in strata output — PARTIAL: verified against MemorySink; re-run on strata
- [x] Docs + license headers

---

## Phase 9 — `tpt-shatter-gateway`
- [ ] axum HTTP/JSON server — PARTIAL: BLOCKED on license policy: axum pulls sync_wrapper (Apache-2.0 only); needs a policy decision
- [x] Capability token validation (HMAC, TTL, scope)
- [ ] Rate limiting (per token hash / per source) — PARTIAL: per token hash done; per source address needs the HTTP layer
- [ ] Route validated requests to the assembler (gRPC, mTLS) — PARTIAL: in-process RecordSource trait done; gRPC needs tonic, which pulls prost (Apache-2.0 only)
- [x] Return responses; uniform error responses that leak nothing
- [x] Logs only token hashes and metadata
- [x] Key rotation signal receiver (from canary) with instant effect
- [ ] Health/readiness endpoints — PARTIAL: readiness logic done; HTTP endpoints wait on the HTTP layer
- [ ] TLS termination config — PARTIAL: pending
- [ ] Verify the gateway has no network path to any vault — PARTIAL: gateway has no vault-client dependency; network isolation is infrastructure work
- [ ] Request size limits, timeouts, header hardening — PARTIAL: pending HTTP layer
- [x] Docs + license headers

---

## Phase 10 — `tpt-shatter-canary`
- [ ] Canary record generator (synthetic high-value records, realistic-looking) — PARTIAL: structured records, not yet realistic
- [x] Secret deterministic prefix scheme
- [ ] Periodic injection into all vaults — PARTIAL: plan supports injection; scheduler pending
- [ ] Canary refresh/rotation schedule
- [ ] Vault query-log tailer (per vault) — PARTIAL: pending
- [ ] Detect canary FragmentId in query logs — PARTIAL: detection on supplied IDs done; log tailing pending
- [x] Alarm: rotate HMAC signing key, invalidate all tokens — PARTIAL: via Responder trait; wiring to the token Signer pending
- [ ] Alarm: notify security (webhook/email/pager integration) — PARTIAL: via Responder trait; real channel pending
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
- [ ] Retention policy enforcement (TTL on fragments)

### Audit trail
- [ ] Define audit event schema (who/what/when via token hash and shard hash, no payload)
- [ ] Implement tamper-evident audit log (hash chain)
- [ ] Compliance export/report tooling

### Disaster recovery
- [ ] Backup/restore runbook per vault
- [ ] Derivation key and token key escrow/recovery procedure
- [ ] Restore drill test

### Schema evolution
- [ ] Schema version stored with fragments
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
- [ ] mTLS between internal services (cert provisioning)
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
- [ ] Memory-safety tests: zeroize called; custom allocator asserts memory zeroed after drop
- [ ] Chaos: kill assembler mid-request, no partial data persists
- [x] Chaos: kill one vault, graceful degradation
- [x] Chaos: partial shred write, saga compensates
- [ ] Pen test: cross-vault query attempts
- [ ] Pen test: token replay, tamper, expiry
- [ ] Pen test: extract data from assembler disk image (expect nothing)
- [ ] Fuzzing for token parser and gRPC inputs
- [ ] Log-scan test: no sensitive values in logs
- [ ] Load/latency benchmarks for read path
- [x] CI runs all non-infrastructure tests

---

## Phase 14 — Documentation, Compliance & Release
- [ ] README (overview, quick start, license)
- [ ] Update `DESIGN.md` with resolved gaps and final decisions
- [ ] Operations runbook (deploy, rotate keys, canary alarm response, DR)
- [ ] Compliance mapping notes: GDPR, PCI-DSS, HIPAA, SOC 2
- [ ] Security review of assembler and token crates
- [ ] Final dependency license audit (`cargo deny check`) and attribution notices
- [ ] Versioning/changelog (`CHANGELOG.md`)
- [ ] Release checklist and tagged `v1.0.0`
