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
- API (verified in the pinned source, `crates/tpt-strata/src`): `Column::new` and
  `Table::try_new` build a table from values. `QueryBuilder::new(&table).group_by(..)
  .aggregate(col, AggFunc::{Sum, Count, Min, Max, Avg}).execute()` returns a grouped table.
  `Table::empty(schema)` returns a typed empty table. An all-NULL column cannot be built,
  because the type cannot be inferred.
- **Durability: none.** The crate has no file or network I/O (`std::fs`, `File`, and
  serialization are absent from `src`). Tables live in memory, and the emitter's JSONL log
  is the only durable copy (see `StrataSink`).

## tpt-strata-parquet (optional Parquet import bridge)

- Lives inside the `tpt-strata` repository under `crates/tpt-strata-parquet`.
- Depends on the `parquet` and `arrow` crates, both **Apache-2.0 only** (verified with
  `cargo info`, versions 55.x).
- **Decision: dropped.** The bridge would violate the MIT-compatible license policy in
  `deny.toml`. The emitter will write to tpt-strata's native format only. `deny.toml` bans
  `parquet` and `arrow`, so CI fails if either is added. Reinstating the bridge would require
  an explicit, documented policy exception and removing those bans.

## Verification pass (checked against `master` via GitHub raw files)

### tpt-keystone-db audit log (canary tail question)
- The audit log is the Mirror layer, source `tpt-keystone/src/mirror/audit.rs`.
- Storage: rows in the table `_mirror_audit` inside keystone's own database.
- Public Rust API: `AuditLog::record`, `AuditLog::verify_chain(session_id)`,
  `AuditLog::generate_report(session_id)`. The read path `entries_for` is private.
- **External access: none found.** No SQL function, wire command, HTTP endpoint, or file
  path exposes the log. A canary can read it only by querying `_mirror_audit` over the
  wire protocol, which is polling, not a stream.
- **Not tamper-evident to outsiders.** Hashes are stored in the same table as the
  entries, so a principal with write access could rewrite the rows and recompute the
  chain. Our `AuditChain` (keyed, separate key) must hold the anchor, so the canary
  should record the chain head outside keystone.
- **Query logging: not verified.** The Mirror docs and `audit.rs` don't say whether
  query text goes into `details`. Until that is checked in `mirror/` or the write path,
  the canary cannot rely on it to see canary FragmentIds in queries.
- Checklist status: partially answered. Polling `_mirror_audit` is possible.
  Whether it captures query text is still open.

### tpt-strata API and durability
- Checked against the cached source at the pinned rev `0439970` (cargo git checkout). The
  API and durability questions are now answered; see the strata section above.
- Consequence: strata cannot be the durable copy of anonymized events. The emitter's
  `StrataSink` writes every event to the fsynced JSONL log first, then keeps a copy in
  memory for strata queries. On restart it rebuilds the view from the log.
- Open with the upstream owner: none for shatter's use. Strata's view is unbounded in
  memory, since nothing evicts events from it.
