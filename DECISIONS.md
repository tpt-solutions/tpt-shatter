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
    for graviola 0.2.1, and the TLS/SCRAM setup for the keystone vault connections.

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
  (`JsonlSink` in `tpt-shatter-emitter`), one object per line, fsynced per batch. Strata
  is rebuilt from that file on start. Strata has no documented persistence (see
  `UPSTREAM.md`), so it must not be the only copy.
- Only policy-approved fields reach the file, so it holds anonymized data only.

## Audit anchoring (added after the upstream check)

- Keystone's `_mirror_audit` chain sits in the same table as the entries, so it isn't
  tamper-evident to an outsider. Our `AuditChain` head hash is written outside keystone
  at each canary poll. A rewrite of `_mirror_audit` then fails against the anchor.
