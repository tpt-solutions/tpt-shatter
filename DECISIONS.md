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

- **Key delivery:** keys are unsealed at boot from a KEK-sealed blob into a tmpfs key
  directory, then kept in RAM only. Built as `tpt-shatter-kek`; see the decision at the end.
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

- **Logging: `tracing` (MIT), structured JSON.** Built. The node binary writes one JSON
  object per line to stderr. Events carry counts, status codes, and token hashes, never
  values, tokens, or shard keys. Sensitive values sit in types whose `Debug` output hides
  them. The leak test covers the access and alert lines. A static lint is still open.
- **Metrics: Prometheus text on a separate listener.** `metrics_listen` (off by default)
  serves `GET /metrics` in Prometheus text format, version 0.0.4. It is for the management
  network, not the read path. Labels use fixed vocabulary only: HTTP status, the gateway's
  public code, and vault label. No value, token, or shard key appears in a sample. The
  text is hand-rendered, so no new metrics crate is needed.
- **OTLP export: through an OpenTelemetry Collector, not in-process (decided).** The
  OpenTelemetry Rust crates are Apache-2.0 only, so they are not linked. A Collector runs
  beside each node as a separate deploy-time process. It reads the node's JSON logs from
  stdout and scrapes `/metrics`, then exports OTLP. The license policy covers linked crates,
  so this is not a linked dependency. An in-process exporter, built as a workspace crate, is
  deferred until a deployment cannot run a sidecar. That is the one fact that would change
  this decision. The gateway's access log already follows this shape.

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
- **Caller identity:** the audit chain records the caller of each issuance, read, and write
  as a keyed digest of the caller tag (see the decisions at the end of this file). The
  access log still carries the caller name.

## BI access (decided)

- **Scheduled exports write CSV files to a local directory.** `analytics.exports` names the
  CSVs and `analytics.export_dir` names where they go. The node rewrites them every
  `analytics.export_interval_secs`. Each file is renamed into place, so a reader never sees a
  partial file. Export file names must be plain names, not paths.
- **No network endpoint for BI.** A query endpoint would need its own authentication, a
  network path to the analytics subnet, and a decision about who may query which groups. None
  of that is built, so the first BI path is a file, and a later endpoint needs its own
  decision.
- **Exports apply the same rules as the one-off command.** Only events inside the retention
  window count, groups under `k` are left out, and spreadsheet formula characters are guarded.

## Decisions taken on the open items (2026-10-13)

- **Vault isolation: each vault becomes its own service.** Decided, not yet built. Each vault
  runs as a separate process on its own host, with its own sealing key and its own storage.
  The node becomes the router: it calls each vault over mTLS, and holds no vault key that
  another vault could use. The first step is a vault service exposing the `put`, `get`,
  `delete`, and `contains` operations the router already uses, behind the same
  `VaultBackend` trait, so the router and assembler do not change. Until this is built, the
  node is a single trust domain and must be described that way.
- **Key delivery: a key directory on tmpfs.** `TPT_KEYS_DIR` names a directory holding one
  file per key, named as in `KEY_VARS`, each with 64 hex characters. On Unix, a file readable
  or writable by group or others is refused. The boot step writes the directory from the
  sealed key material, so the KEK never reaches the node. The `TPT_KEY_*`
  environment variables remain for development only, since they leak through `/proc` and
  child processes. The KEK tool (see the end of this file) is the on-prem path.
- **Caller identity in the audit chain.** Tokens are now version 2. Each token carries a
  16-byte caller tag, the first 16 bytes of SHA-256 of the caller's name. The tag is covered
  by the token signature. The issuer tags every token with its caller, and the gateway passes
  the verified tag to the audit hook. The chain stores only a keyed digest of the tag. An
  event without a caller has no `caller` key in its log line and adds nothing to its MAC, so
  lines from before this change still verify. This was checked against a log written by the
  pre-change code: it verifies under the current code, and it still verifies after attributed
  records are appended. Version 1 tokens are refused after the upgrade.
  Their lifetime is at most 60 seconds, so the switch needs no migration, only that no
  token issued before the deploy is still expected to work.

## Decisions taken on the remaining open items (2026-10-13, second round)

- **Vault split: built as a service, one per vault.** `tpt-shatter-vault-service` serves one
  vault over mTLS (HTTP/1.1 over TLS 1.3, one request per connection). Its `RemoteVault`
  implements `VaultBackend`, so the router, assembler and shredder are unchanged. The node
  uses `remote_vaults` in place of local directories and then holds no vault keys:
  `Keys.vaults` is `None`, and the three vault keys are optional together. Each service
  holds only its own sealing key and runs its own retention purge. Tested over loopback mTLS,
  including a client without a certificate and a wrong server name, and with a full node
  round trip through three services. Not yet measured: the cost of one TLS connection per
  request, which has no pooling or retry. The services are not deployed by any config yet.
- **Key protection: a narrow KEK tool, not a KMS (`tpt-shatter-kek`).** A KMS was
  considered and rejected. OpenBao (MPL-2.0) was the first choice, but it is a second
  system to run and secure for one wrapping key, and no MIT server alternative was found.
  Building a general KMS would add a high-value component that we would be the least
  reviewed on. What the node needs is one key-encryption key (KEK) that is kept outside it.
  The tool seals the node's keys under a random KEK with ChaCha20-Poly1305, and splits the
  KEK 2-of-3 among custodians with Shamir's scheme. Unseal writes the keys into
  `TPT_KEYS_DIR` on a tmpfs.
  - **Shamir library: `blahaj` 0.6.0 (MIT).** `sharks` 0.5.0 was the first choice. It is
    rejected because RUSTSEC-2024-0398 says its coefficients are drawn from 1..=255, which
    biases the shares. `cargo deny` caught it. `blahaj` is the maintained fork and draws from
    0..=255.
  - **Not audited.** Neither the Shamir library nor this tool has been independently
    reviewed. The tool has no access control and no audit log of its own, so the custody
    procedure in the runbook is part of the security boundary.
  - **Both custody modes are supported, and the blob records which one it uses.**
    - *Shamir custody (on-prem):* the KEK is split 2-of-3 among custodians, as above.
    - *Wrapped custody (cloud):* the KEK is wrapped by the cloud KMS through an
      operator-supplied program, named only on the command line. The program receives hex
      on stdin and prints hex on stdout, so the operator writes a small wrapper around the
      cloud CLI. The blob stores the wrapped KEK. The library has no cloud SDK, so it
      needs no new licenses, and the cloud service's own audit covers the KEK.
    - The custody mode is authenticated in the blob header, so a wrapped blob cannot be
      opened in Shamir mode, or the reverse (tested).
    - **Not tested against a live cloud KMS.** The wrapped path was run end to end on
      Windows with a stand-in program; the Unix integration test uses `rev` and was not run
      on this machine.
- **Key files for vault services.** Each vault service reads its key from a file of 64 hex
  characters, refused unless it is mode 0400 or 0600 on Unix, and it never reads the node's
  keys.

## Kubernetes layout and per-vault names (2026-10-15)

- **Per-vault certificate names.** Each vault service runs in its own namespace, so its
  certificate carries its own name. `RemoteVaults` takes an optional `server_names` map,
  one name per vault. Without it, `server_name` applies to all three vaults, as before.
  Partial maps are refused.
- **One node process, one pod.** The node runs the gateway, assembler, shredder, canary,
  issuer, and analytics feed in one process, so the spec 6.1 gateway-in-DMZ separation is
  not expressible yet. The manifests put the whole node in a private namespace, with an
  edge rule that reaches it on the read port only. Splitting the gateway from the node
  needs the canary dependency removed from the gateway crate.
- **Node state on disk (exception to spec 6.2).** The audit chain, the orphan queue, and
  the analytics log live in `state_dir`, which needs persistent storage. The manifests
  allow one PVC for it, and the OPA rules allow only that claim on the node. This is a
  deliberate exception, pending a decision on where that state should live. Remove the
  exception when that decision is made.
- **Policies as code.** Admission rules and NetworkPolicy rules are written in Rego under
  `infrastructure/policies/`, with unit tests run by `opa test`. They are a starting point,
  not yet run as a live admission webhook. See `infrastructure/README.md`.

## Assembler service and the gateway link (2026-10-15)

- **Transport: HTTP/1.1 over mTLS, not gRPC.** The gateway calls the assembler the same way
  it calls the vault services: one request per connection, TLS 1.3, client certificate
  required. The record crosses this link as `{"fields": {...}}`. Errors cross as a code,
  plus the vault label where one applies.
- **Alarm types moved to common.** `Alarm` and the `Responder` trait live in
  `tpt-shatter-common`, and canary re-exports them. The gateway implements its responder
  without depending on canary. That dependency reached the vault client, so the gateway's
  tree no longer contains vault, assembler, or shredder crates.
- **`ServiceUnavailable`.** A new error for a service this one depends on that cannot be
  reached or does not answer. The gateway maps it to `503`, the same as a vault outage.
- **Open: canary in the split.** The assembler service does not attach the router observer,
  so a canary read that goes through it raises no alarm. The alarm response also rotates
  the gateway's token key, which cannot reach a gateway on another host yet. Until that
  propagation exists, the canary observer must stay where the alarm response can reach the
  gateway. Do not split the node without deciding this.
- **Open: read audit in the split.** The gateway records each authorized read in the audit
  chain, which is keyed by `TPT_KEY_AUDIT`. A gateway host would need that key, or the
  audit writes would need to move. This needs a decision before a standalone gateway
  binary is built.

## Gateway service (2026-10-15): decisions on the two open items

The two open items in "Assembler service and the gateway link" are decided as follows.

- **Read audit uses the gateway's own key and chain.** `tpt-shatter-gateway` writes
  `gateway-audit.jsonl` under its own `audit_key_file`. It never receives `TPT_KEY_AUDIT`,
  so compromising the DMZ host does not expose the node's chain. The two chains are checked
  separately. Verifying across both is an offline step that needs both keys, held by
  different custodians. Writes are not served by the gateway, so the gateway audits reads
  only.
- **Canary alarms are not propagated to the gateway.** The gateway refuses to start unless
  `acknowledge_canary_gap` is `true`. The node keeps the canary observer, and its response
  rotates only the node's signing key. Until alarm propagation exists, a canary read does
  not revoke tokens on a split gateway. The flag records that acceptance in the config
  itself. Building propagation (alarm to gateway over the management network, then rotation
  there) is the next step before this split is used in production.
- **Readiness covers the gateway process only.** Assembler health is not in `/readyz` yet.
- **Dependency security fix.** `cargo deny check` reported RUSTSEC-2026-0346 through
  -0349 against rustls 0.23.45. The lockfile now pins rustls 0.23.46, the first fixed
  release. Only rustls was updated.
- **Shared code moved to common.** `AuditStore`, `keyed_digest`, and `read_key_file` moved
  into `tpt-shatter-common`, so the gateway can use them without depending on the node or
  the vault crates. The old paths re-export them.

## Canary alarm propagation (2026-10-16)

- **Transport and identity.** The node pushes a rotation to each gateway's alarm listener
  over mTLS HTTP. The listener requires a client certificate that chains to its own
  `client_ca`, so only the node can reach it. Keep the alarm CA separate from the assembler
  CA, so a certificate issued for one link does not open the other.
- **Who chooses the key.** The node generates the new key and pushes it. Each gateway
  installs it only if its version is newer than the one it holds. A stale version is
  refused with `409`, so a replayed or reordered push cannot roll a gateway back.
- **Order of switching.** The node switches only after every peer has accepted. A failed
  push leaves the node on the old key and the alarm gate armed, so the next monitor pass
  retries. Peers that already accepted stay on the new key. Their tokens are then refused
  until the retry completes, which fails closed.
- **Audit before switch.** A gateway writes the rotation to its audit chain before it
  changes the key. If the write fails, the key does not change.
- **Gateway config.** An `alarm` listener satisfies the canary requirement. Without one, the
  gateway still refuses to start unless `acknowledge_canary_gap` is set.
- **Open, and stated in the runbook.**
  - Rotation is not durable. A restart reloads keys from provisioning. The node and every
    gateway must restart from the same key set, or they disagree and fail closed.
  - The new key travels inside a JSON body, and the body is parsed without zeroizing.
    Confidentiality rests on the mTLS link alone.
  - **Canary detection does not run in the assembler service.** `tpt-shatter-assembler`
    does not attach `CanaryWatch` to its router, so a canary read made through it raises no
    alarm. The node detects canary reads only when the node serves them itself. Attach the
    observer, and give the assembler the canary master key, before the assembler runs on its
    own host.
