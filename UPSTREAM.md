# Upstream Dependencies

Verified facts about the TPT upstream projects that tpt-shatter depends on. Checked
against the `tpt-solutions` GitHub organization. Pins are the `master` HEAD commits at the
time of checking. Re-verify and replace them with tags before any release.

## tpt-keystone-db (identity, demographic, and financial vaults)

- Repository: https://github.com/tpt-solutions/tpt-keystone-db
- Pin checked: `b861edd6f01e08061e0e1f3a86e6a2a1e1f2f449` (master)
- License: `MIT OR Apache-2.0` (per `LICENSE`). GitHub's API reports "Other", so the
  license file is authoritative. Compatible with our policy.
- Client integration: **Postgres wire protocol** (decision). The project is documented as
  Postgres wire-compatible and has no documented embedding API for Rust. The vault client
  will use a standard Postgres client crate (MIT/Apache-2.0).
- Auth and transport: SCRAM-SHA-256 and TLS exist (Phase 18 of keystone's own plan), but
  they are opt-in. They only activate when roles are populated or
  `TPT_TLS_CERT_PATH` / `TPT_TLS_KEY_PATH` are set. Our deployment config must set them.
- Audit: keystone documents a hash-chained audit log and session replay. **Not yet verified:**
  whether the query log can be tailed by the canary service (Phase 10). This is an open item.

## tpt-strata (insight-vault analytics sink)

- Repository: https://github.com/tpt-solutions/tpt-strata
- Pin checked: `0439970ca3fd371be2d2696f308445cf5987ca4f` (master)
- License: `MIT OR Apache-2.0` (per `Cargo.toml` and the `LICENSE-MIT` / `LICENSE-APACHE` files).
  Compatible with our policy. The GitHub API's Apache-2.0 label is incomplete.
- Deployment: embeddable, in-process, with no server process. The README reports zero
  external dependencies for the core crate. Confirmed.
- **Not yet verified:** the builder API for ingest, group-by, and sum, and the durability model.

## tpt-strata-parquet (optional Parquet import bridge)

- Lives inside the `tpt-strata` repository under `crates/tpt-strata-parquet`.
- Depends on the `parquet` and `arrow` crates, both **Apache-2.0 only** (verified with
  `cargo info`, versions 55.x).
- **Decision: dropped.** The bridge would violate the MIT-compatible license policy in
  `deny.toml`. The emitter will write to tpt-strata's native format only. `deny.toml` bans
  `parquet` and `arrow`, so CI fails if either is added. Reinstating the bridge would require
  an explicit, documented policy exception and removing those bans.
