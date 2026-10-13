# Decision Log

Decisions taken to close the Phase 0 items in `todo.md`. Each one states the choice,
the reason, and what it changes. Where a decision is only recorded and not built yet,
that is said. Changing a decision means editing this file and the checklist together.

## Licensing

- **Policy:** linked crates must be MIT-compatible. Bare `Apache-2.0` is rejected by
  `deny.toml`. Dual `MIT OR Apache-2.0` and the other allow-listed licenses pass.
  Deploy-time tools (OPA, Distroless, Terraform) are exempt.
- **Banned, with reasons:**
  - `parquet`, `arrow`: Apache-only. The Parquet bridge is dropped (see `UPSTREAM.md`).
  - `prost`: Apache-only. This blocks `tonic` (gRPC). See Transport below.
  - `sync_wrapper`: Apache-only. This is pulled in by `axum`, so `axum` is not used.
- **Dependency audit:** `cargo deny check` passes on the current tree. Planned crates
  were checked with `cargo info`: `hyper`, `hyper-util`, `tokio` are MIT. `axum` and
  `tonic` are MIT but depend on Apache-only crates. `ring` is `Apache-2.0 AND ISC`
  (see TLS below).

## Transport

- **HTTP server: hyper 1 + tokio, not axum.** `axum` would add `sync_wrapper`
  (Apache-only). `hyper` avoids it. Implemented in
  `crates/tpt-shatter-gateway/src/http.rs`: liveness, readiness, and the read route.
- **Internal service-to-service transport: HTTP/JSON over hyper, not gRPC.** `tonic`
  requires `prost` (Apache-only). Reconsider gRPC only if an MIT-compatible protobuf
  stack becomes available. Not yet built: the assembler's internal interface.
- **TLS and mTLS: rustls 0.23 with the graviola crypto provider, no policy exception.**
  - `ring` (`Apache-2.0 AND ISC`) and `aws-lc-sys` (contains plain Apache-2.0 parts)
    both break the policy, so neither is used. No exception is needed.
  - Provider: `rustls-graviola` **pinned to `=0.2.1`**. It is pure Rust, and the ISC
    option of its `Apache-2.0 OR ISC OR MIT-0` license satisfies `deny.toml`.
  - Version 0.3.x pulls in `libcrux-ml-kem` and Apache-only `hax-lib` and
    `libcrux-intrinsics`, plus three open advisories (RUSTSEC-2026-0207, -0208,
    -0212). Version 0.4.x needs Rust 1.89, above the workspace's 1.85. Do not upgrade
    without re-running `cargo deny check`.
  - Risk: graviola is pre-1.0 and has not had an independent audit as far as this
    project has checked. Treat the TLS path as a reviewed dependency to revisit at each
    release, and keep an eye on its advisories.
  - Only TLS 1.3 is offered. mTLS is supported: the server requires a client
    certificate chaining to a configured CA.
  - Implemented in `crates/tpt-shatter-gateway/src/tls.rs` and `http.rs` (`serve_tls`).
    Tested with real handshakes in `crates/tpt-shatter-gateway/tests/tls.rs`, using
    test-only certificates in `tests/fixtures/` (see the README there).
  - Still open: certificate issuance and rotation for services, the 1.85 MSRV check
    for graviola 0.2.1, and the TLS/SCRAM setup for the keystone vault connections (superseded: keystone was dropped, see "Vault storage").

## Data model

- **Field-to-vault allocation (recommended, editable in config):**
  - Vault A (identity): `name`, `email`, `phone`, `street_address`, `national_id`.
  - Vault B (demographic): `birth_year`, `gender`, `postcode_prefix`, `country`.
  - Vault C (financial and sensitive): `card_number`, `bank_account`, `annual_income`.
  - The schema loader (`ShatterSchema::load_json_file`) takes this mapping as data, so
    it can change without a code change.
- **ShardKey:** 256-bit CSPRNG value, 64 hex characters (implemented in
  `tpt-shatter-common`).
- **FragmentId:** keyed HMAC-SHA256 of the ShardKey with a per-vault domain tag, so no
  mapping table is needed (implemented in `tpt-shatter-vault-client`).
- **Schema versioning:** version is part of the schema, and the version should be stored
  with each fragment. Storing it with fragments is not built (needs shredder changes).

## Capability tokens

- **Format:** as implemented in `tpt-shatter-token`. Version 1, HMAC-SHA256, bound to a
  ShardKey and scopes. Default TTL 60 seconds, maximum 300 seconds, clock-skew allowance
  5 seconds.
- **Issuer contract (recommended):** the host application authenticates the user
  upstream, then calls an internal issuer endpoint with the ShardKey and the requested
  scopes. The issuer returns a token. Upstream authentication is out of scope.
- **Replay:** short TTL and no reuse of nonces across the gateway. No session store.

## Anonymization

- **Minimum cohort (k):** 10. Releases below this are suppressed.
- **Noise:** Laplace mechanism, epsilon 1.0 per released statistic. Budget accounting
  across queries is still open.
- **Bucketing:** birth year into 10-year bands. Income into fixed-width bands, with width
  set per dataset.
- **Display masking:** keep the last 4 characters.
- **Pseudonymization salt:** provisioned through the same RAM-only path as the derivation
  key. Rotated each analytics period (quarterly recommended). Rotation breaks linkage
  across periods, which is intended. Rotation tooling is not built.

## Canary and alarm response

- **Canary keys:** derived from a master canary key and a rotation epoch
  (`CanaryPlan::for_epoch`). The recommended epoch length is 7 days (`epoch_at`).
  The canary key is separate from the derivation key.
- **Alarm response:** rotate the signing key locally, invalidating outstanding tokens,
  then notify security. Propagating the new key to the issuer and gateways is a
  recommendation only: they pull the key from a key store, with at most 60 seconds of
  staleness. Not built.

## Identity between services

- **mTLS identity (recommended, not built):** a private CA. One certificate per service,
  with the service name as the SAN. Lifetime 24 hours, renewed automatically. Depends on
  the TLS decision above.

## Keys and disaster recovery

- **Key delivery:** keys are unwrapped at boot from a KMS-held wrapping key, then kept
  in RAM only. Not built.
- **Custody:** split across three custodians, 2-of-3 to recover.
- **Backups:** per-vault, encrypted, with a recovery point objective of 24 hours and a
  recovery time objective of 4 hours. Restore drills are quarterly.
- **Erasure:** delete by FragmentId in every vault, then write a tombstone. Backups are
  handled by expiry or by replaying tombstones on restore.

## Audit

- **Chain:** keyed HMAC-SHA256 over the previous MAC and the event, with a separate
  chain key. Implemented as `AuditChain` in `tpt-shatter-common`. Durable storage and
  export are not built.

## Storage and analytics

- **Strata deployment: embedded.** `tpt-strata` runs in-process with no server
  (confirmed against its README, see `UPSTREAM.md`). There is no sidecar.
- **Analytics access:** read-only, from the analytics subnet, inbound only from the
  emitter.

## Observability

- **Logging: `tracing` (MIT), structured JSON.** Not built yet. Sensitive values are
  wrapped in redacting types so they cannot be formatted.
- **OTLP export: deferred.** The OpenTelemetry Rust crates are Apache-2.0, so they are
  not used. Until an MIT-compatible OTLP exporter is verified, logs go to stdout as JSON
  and a collector agent ships them. The gateway's access log already follows this shape.

## Analytics durability (added after the upstream check)

- **The durable copy of anonymized events is an append-only JSON-lines file**
  (`StrataSink` in `tpt-shatter-emitter`), one object per line, fsynced per batch. Strata
  is rebuilt from that file on start. Strata has no documented persistence (see
  `UPSTREAM.md`), so it must not be the only copy.
- Only policy-approved fields reach the file, so it holds anonymized data only.

## Analytics retention and feed (decided)

- **Retention: analytics events live as long as vault fragments**, `retention_secs`
  (30 days by default). Each log line carries its storage time. `StrataSink::purge_before`
  removes older events from the log, rewritten through a temp file and rename, and from
  the view. Memory is therefore bounded by the window and the ingest rate. A separate
  analytics retention knob was not added, because a longer window would keep more
  identifying detail about the same people than the vault keeps.
- **Feed: anonymize at ingest, gate at flush.** Each accepted write is anonymized before
  it is stored. Only the anonymized event is held, never the raw record. Held events are
  emitted once the k-anonymity gate passes over all of them. Events not yet emitted when
  their window ends are dropped. A write whose anonymization fails is refused, so an
  event never exists for a write that was not stored.
- **Policy file and salt.** The policy is a JSON file named by `analytics.policy` in the
  node config. The pseudonym salt is `TPT_KEY_ANALYTICS`, which is required even when
  analytics is off, so the key set is the same on every node.
- **Known gaps:** the feed holds events in memory until the gate passes, so a low-volume
  node may hold a few events for a long time. The gate is checked over everything held,
  so one small cohort can hold back all analytics output until it grows.

## Audit anchoring (added after the upstream check)

- (Superseded: keystone was dropped, see "Vault storage".) Keystone's `_mirror_audit` chain sits in the same table as the entries, so it isn't
  tamper-evident to an outsider. Our `AuditChain` head hash is written outside keystone
  at each canary poll. A rewrite of `_mirror_audit` then fails against the anchor.

## Vault storage (supersedes keystone)

- **Decision: replace tpt-keystone-db with an internal vault store, `FileVault`**
  (`crates/tpt-shatter-vault-client/src/file_vault.rs`). Each vault is its own directory
  with its own sealing key, and each fragment is one encrypted file.
- **Why keystone was dropped.** Verified in the source (see `UPSTREAM.md`):
  - Every insert, update, and delete publishes the full before and after row, in
    plaintext, to a `__cdc_<table>` topic with unlimited retention. There is no per-table
    opt-out and no way to purge a deleted row's history. That defeats GDPR erasure for
    fragments.
  - The audit log (`_mirror_audit`) and the tracer are not called from the server's
    production path. They are used only by tests.
  - Query text is not logged, so canary query detection could not rely on keystone.
  - We only need lookup, write, and delete by FragmentId. A keyed file store does that
    directly, so keystone's SQL engine adds nothing here.
- **What FileVault provides:**
  - Encryption at rest with ChaCha20-Poly1305. The vault label and FragmentId are bound
    as associated data, so a file moved between vaults or IDs fails to open.
  - Atomic writes: temporary file, sync, rename. Leftover temporary files are removed
    when the vault opens.
  - Erasure: overwrite with zeros, sync, remove. Nothing keeps a change history.
  - Isolation: separate directory and key per vault. Key delivery is still a gap.
- **What we now own, and do not have yet:**
  - Replication and high availability. A vault is one directory on one volume.
  - Backups and restore. These are needed before production (see RUNBOOK).
  - Overwrite-based erasure is not guaranteed on SSDs with wear leveling or on
    copy-on-write file systems. Encryption is what protects erased data in that case, so
    key destruction must be part of erasure for those volumes. **Not built.**
  - Concurrency and performance at scale. The store is intended for the current volume.
- **Consequences for other decisions:**
  - Vault TLS and SCRAM are no longer needed for vault connections, because vaults are
    local files. Vault traffic is in-process.
  - Canary query-log tailing is replaced by in-band detection in the vault client: the
    router checks each FragmentId it reads or deletes against the canary detector.
    In-band detection does not see direct access to a vault's files on the host.
    That case needs host-level monitoring, which is not built.
  - Keystone's audit anchoring is not needed. The keyed `AuditChain` remains the audit
    trail.

## Canary detection in the vault client (supersedes the query-log plan; access model revised below)

- **Decision: detect canaries in the router, not in a database query log.** The router
  reports every read to a `ReadObserver`. `CanaryWatch` (canary crate) checks each
  FragmentId against the current epoch's canaries and queues an alarm on a hit. Nothing
  in the system reads a canary on purpose, so any hit is suspicious.
- **Only reads are observed.** Deletes and writes are not. Erasure and canary rotation
  both delete, and a delete alone cannot be told apart from them. Erasure verifies by
  presence, through `Router::contains`, which is not observed. Otherwise every rotation
  would alarm on its own old canaries. This was found by a failing test and fixed.
- **Trade-off:** `Router::contains` lets a caller learn whether a FragmentId exists
  without raising an alarm. The method is inside the trust boundary, but it is still a
  weakness. Restricting it to erasure is a follow-up.
- **Not covered:** direct access to a vault's files on the host, and any caller that
  bypasses the router. Host-level monitoring is needed for those and is not built.
- **Not yet wired:** a loop that drains `CanaryWatch::take_alarms` into `AlarmGate`, and
  into the alert log.

## Canary access model (revised: supersedes the read-only observation above)

- **Observed:** `Router::get` (reads) and `Router::delete` (deletes). Both reach the
  `AccessObserver`, and `CanaryWatch` alarms on either one hitting a canary.
- **Not observed:** `Router::put` (ingestion and canary injection write), and the
  `*_maintenance` methods, used for erasure, canary rotation, saga compensation, and orphan
  reaping. Maintenance is what used to force a choice between a false-alarm storm and an
  existence oracle. Now it is a separate, explicit path.
- **Why this is still an in-process boundary:** anyone who holds the `Router` can call the
  maintenance methods, so this is a convention enforced by which code holds the router. The
  external API (gateway and assembler) only reaches `get`, and deletes are not exposed
  there. This is the accepted trust boundary for now.
- **Closed:** the earlier `contains` presence oracle is gone. Erasure verifies through
  `contains_maintenance`, which is only reachable from maintenance code.
- **Response loop:** `CanaryMonitor::poll` drains the watch, runs the `AlarmGate`
  response, then writes each alarm to the alert log. A failed response requeues the alarms
  and keeps the gate armed, so nothing is lost on failure. Nothing calls `poll` on a timer
  yet.

## Token issuer (built)

- **Contract (unchanged from above):** the host application authenticates the user upstream,
  then calls `POST /v1/tokens` on the issuer listener with a shard and the scopes it needs.
- **Caller authentication:** a bearer secret per caller. The config holds only the SHA-256
  of each secret. Every caller is compared on every request with no early exit, so timing
  does not reveal which caller matched. Chosen over per-caller certificates because the
  node does not yet expose peer certificates to handlers. mTLS still applies when
  `client_ca` is configured, since the listener shares the TLS acceptor.
- **Policy:** each caller has an allowed scope list and a maximum TTL. `read` and `write`
  are issuable. `delete` is never issuable, because erasure is a maintenance operation and
  must not depend on a token. The default TTL is 60 seconds, the signer's maximum is 300,
  and a caller's maximum is checked against both.
- **Audit before release:** every issuance is appended to a keyed hash chain
  (`state_dir/audit.jsonl`, sealed with `TPT_KEY_AUDIT`) and synced before the token is
  returned. If the append fails, the token is withheld. After a failed write the store
  refuses further records until restart, because the in-memory chain is then ahead of the
  file. A restart verifies the whole chain before resuming it.
- **Known gaps:** the audit event has no caller field, so the chain cannot say which caller
  issued a token. The access log carries the caller name. Adding the field changes the
  event format and needs a decision on how caller names are recorded.
