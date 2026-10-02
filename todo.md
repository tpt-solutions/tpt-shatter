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
- [ ] Verify `tpt-keystone-db` license is compatible (GitHub)
- [ ] Verify `tpt-strata` and `tpt-strata-parquet` licenses are compatible (GitHub)
- [ ] Verify Parquet-related transitive deps (arrow/parquet crates are Apache-only?) and decide whether `tpt-strata-parquet` can be used

### Upstream integration
- [ ] Record GitHub URLs, commit/tag pins for tpt-keystone-db and tpt-strata
- [ ] Review tpt-keystone-db Rust API / wire protocol; choose native API vs wire client
- [ ] Confirm keystone supports SCRAM-SHA-256 + TLS as the spec assumes
- [ ] Confirm keystone exposes a query log / audit hook the canary can tail; if not, file/implement the feature upstream
- [ ] Review tpt-strata embedding API (in-process ingest, group by, sum) and its durability model
- [ ] Confirm tpt-strata never needs a separate server process

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
- [ ] Initialize git repository
- [ ] Create Cargo workspace root `Cargo.toml` (shared package metadata: `license = "MIT OR Apache-2.0"`, authors TPT Solutions)
- [ ] Add `LICENSE-MIT` (TPT Solutions)
- [ ] Add `LICENSE-APACHE`
- [ ] Add `NOTICE` file
- [ ] Add license section to `README.md`
- [ ] Add SPDX headers convention (`MIT OR Apache-2.0`) and enforce it
- [ ] Rename/move `spec.txt` -> `DESIGN.md` (formatted markdown, per spec section 3)
- [ ] Create `.gitignore`, `rust-toolchain.toml`, `rustfmt.toml`, clippy config
- [ ] Scaffold 9 crates under `crates/`: common, token, gateway, shredder, assembler, emitter, canary, anonymize, vault-client
- [ ] Scaffold directories: `vaults/vault-frag-{a,b,c}`, `insight-vault/`, `infrastructure/{terraform,k8s,policies}`, `tests/{integration,canary}`
- [ ] Add `deny.toml` (cargo-deny) that rejects Apache-only licenses and bans unwanted crates
- [ ] Add GitHub Actions CI: fmt, clippy, test, cargo-deny, cargo-audit
- [ ] Add `CONTRIBUTING.md` stating contributions are dual-licensed MIT OR Apache-2.0
- [ ] Set up `cargo-deny` license check as a required CI gate
- [ ] Add `SECURITY.md` (disclosure process)
- [ ] Add workspace-wide lint rules: forbid `unsafe` except in explicitly audited modules; forbid logging macros on sensitive types

---

## Phase 2 — `tpt-shatter-common`
- [ ] `FragmentId` opaque type (no Display of raw value; redacted Debug)
- [ ] `ShardKey` routing key type
- [ ] `CapabilityToken` parsed struct
- [ ] `ShatterError` unified enum (thiserror) with non-leaking messages
- [ ] `SecureZero` trait + zeroize-based helpers
- [ ] `Zeroizing`-wrapped sensitive record types; ensure no `Clone`/`Debug` leaks
- [ ] Vault identifier enum / labels (A, B, C)
- [ ] Shatter schema types (field -> vault mapping), versioned
- [ ] Unit tests for all types
- [ ] Docs + license headers

---

## Phase 3 — `tpt-shatter-anonymize`
- [ ] `bucket()` categorical range bucketing
- [ ] `pseudonymize()` one-way SHA-256 with static salt (salt provisioning + rotation notes)
- [ ] `add_noise()` Laplace mechanism (differential privacy, configurable epsilon)
- [ ] `check_k_anonymity()` small-cohort gate
- [ ] `mask()` UI display masking
- [ ] Property-based tests (determinism, bounds, no PII in output)
- [ ] Statistical tests for Laplace noise distribution
- [ ] Docs + license headers

---

## Phase 4 — `tpt-shatter-token`
- [ ] 256-bit entropy token generation (CSPRNG)
- [ ] HMAC-SHA256 signing and constant-time verification
- [ ] Stateless validation (no session store)
- [ ] TTL enforcement (default 60s) with bounded clock-skew tolerance
- [ ] Bind token to ShardKey and action scopes
- [ ] Signing key versioning + instant rotation (invalidate all active tokens)
- [ ] Token issuer service/endpoint (called by host app after upstream auth)
- [ ] Replay-resistance decision implemented (e.g. nonce/short TTL only) and documented
- [ ] Unit tests: expiry, tamper, wrong scope, wrong shard, wrong key, rotated key
- [ ] Fuzz tests for token parser
- [ ] Docs + license headers

---

## Phase 5 — `tpt-shatter-vault-client` & Vaults
- [ ] Typed read/write ops per vault schema (A, B, C)
- [ ] Connection pooling
- [ ] Enforce single-vault queries only (no cross-vault joins at client level)
- [ ] TLS + SCRAM-SHA-256 connection setup
- [ ] Timeouts, retries, circuit breaker per vault
- [ ] Vault connection status reporting (for observability)
- [ ] Delete-by-FragmentId operation (needed for GDPR)
- [ ] Mock/in-memory vault implementation for tests
- [ ] `vaults/vault-frag-a` config: tpt-keystone-db instance (identity)
- [ ] `vaults/vault-frag-b` config: tpt-keystone-db instance (demographic)
- [ ] `vaults/vault-frag-c` config: tpt-keystone-db instance (financial/sensitive)
- [ ] Per-vault credentials and separate secrets; no shared creds
- [ ] Storage config (S3/local-fs + NVMe cache-aside), no replication between vaults
- [ ] Per-vault automated backup config
- [ ] Docs + license headers

---

## Phase 6 — `tpt-shatter-shredder`
- [ ] Configurable shatter schema loader (versioned)
- [ ] Split record into N fragments per schema
- [ ] FragmentId derivation (keyed HMAC, per-vault domain separation), no mapping table
- [ ] Parallel dispatch to vaults via vault-client
- [ ] Saga/compensation on partial write failure (roll back orphan fragments)
- [ ] Idempotent writes / retry safety
- [ ] Securely zero original record after dispatch
- [ ] Internal gRPC (tonic) ingestion service with mTLS
- [ ] Derivation key loading (RAM only, from provisioning mechanism)
- [ ] Orphan fragment reaper (background)
- [ ] Unit + integration tests with synthetic records
- [ ] Docs + license headers

---

## Phase 7 — `tpt-shatter-assembler`
- [ ] Derive FragmentIds from ShardKey
- [ ] Parallel fetch from all vaults
- [ ] Reconstruct record in RAM only
- [ ] Pass record to emitter, return to gateway
- [ ] Zero all memory on completion and on every error path
- [ ] `mlock` / `mlockall` usage with CAP_IPC_LOCK; fail closed if unavailable
- [ ] Disable core dumps (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE`)
- [ ] Per-request timeout; abort cleanly and zero on cancellation
- [ ] Handle missing/partial fragments safely (no partial record returned)
- [ ] Internal gRPC (tonic) interface for the gateway, with mTLS
- [ ] Statically linked build (musl) with no shell
- [ ] Memory-safety tests (see Phase 13)
- [ ] Docs + license headers

---

## Phase 8 — `tpt-shatter-emitter` & `insight-vault`
- [ ] Apply anonymization transforms (bucket, pseudonymize, noise)
- [ ] k-anonymity gate before emit
- [ ] Emit to embedded tpt-strata engine
- [ ] Signal assembler to zero record after emit
- [ ] `insight-vault/` setup: strata storage layout and schema for anonymized events
- [ ] Decide embedded vs sidecar deployment for strata
- [ ] Decide on tpt-strata-parquet bridge (based on Phase 0 license result)
- [ ] Sample aggregation queries (sum, group by) for BI access
- [ ] Analytics subnet access path for BI tools (emitter-only inbound)
- [ ] Tests: no raw PII present in strata output
- [ ] Docs + license headers

---

## Phase 9 — `tpt-shatter-gateway`
- [ ] axum HTTP/JSON server
- [ ] Capability token validation (HMAC, TTL, scope)
- [ ] Rate limiting (per token hash / per source)
- [ ] Route validated requests to the assembler (gRPC, mTLS)
- [ ] Return responses; uniform error responses that leak nothing
- [ ] Logs only token hashes and metadata
- [ ] Key rotation signal receiver (from canary) with instant effect
- [ ] Health/readiness endpoints
- [ ] TLS termination config
- [ ] Verify the gateway has no network path to any vault
- [ ] Request size limits, timeouts, header hardening
- [ ] Docs + license headers

---

## Phase 10 — `tpt-shatter-canary`
- [ ] Canary record generator (synthetic high-value records, realistic-looking)
- [ ] Secret deterministic prefix scheme
- [ ] Periodic injection into all vaults
- [ ] Canary refresh/rotation schedule
- [ ] Vault query-log tailer (per vault)
- [ ] Detect canary FragmentId in query logs
- [ ] Alarm: rotate HMAC signing key, invalidate all tokens
- [ ] Alarm: notify security (webhook/email/pager integration)
- [ ] Alarm event logging (event only, never canary values)
- [ ] Rate-limited alarm handling to avoid alert storms; manual re-arm procedure
- [ ] Management-subnet-only access to vaults and gateway
- [ ] Docs + license headers

---

## Phase 11 — Cross-Cutting Capabilities
### GDPR / retention
- [ ] Deletion orchestrator service (delete by FragmentId across all vaults)
- [ ] Deletion verification and idempotency
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
- [ ] Unit tests for all 9 crates using synthetic data
- [ ] Integration: full pipeline (shred -> vaults -> assemble -> emit -> strata)
- [ ] Integration: fragments land in the correct vault only
- [ ] Integration: assembler reconstructs record exactly
- [ ] Integration: emitter writes to tpt-strata and output is anonymized
- [ ] Canary tests: inject, query, alarm fires, tokens revoked
- [ ] Memory-safety tests: zeroize called; custom allocator asserts memory zeroed after drop
- [ ] Chaos: kill assembler mid-request, no partial data persists
- [ ] Chaos: kill one vault, graceful degradation
- [ ] Chaos: partial shred write, saga compensates
- [ ] Pen test: cross-vault query attempts
- [ ] Pen test: token replay, tamper, expiry
- [ ] Pen test: extract data from assembler disk image (expect nothing)
- [ ] Fuzzing for token parser and gRPC inputs
- [ ] Log-scan test: no sensitive values in logs
- [ ] Load/latency benchmarks for read path
- [ ] CI runs all non-infrastructure tests

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
