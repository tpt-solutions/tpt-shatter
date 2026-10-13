# Compliance Mapping Notes

Engineering notes that map common regulatory controls to what tpt-shatter does today, and
what is still open. This is not legal advice and not an audit. Each claim names the code or
runbook section that backs it, and each gap is marked **GAP**. The spec's section 11 is the
earlier summary; where it claims more than the code does, this file takes precedence.

## Evidence the node can produce

| Evidence | How to get it | Notes |
|---|---|---|
| Audit chain summary (counts by action and vault, time range, head MAC) | `tpt-shatter-node export-audit <config.json>` | Verifies the chain under `TPT_KEY_AUDIT` first; a tampered chain gives an error and no report. Holds no digests or values. |
| Analytics CSV, k-anonymous | `tpt-shatter-node export-analytics <config.json> <group> [value]` | Groups under k are suppressed. |
| Access log (per request, token and shard hashes) | Node stderr, one JSON object per line | Never contains values, tokens, or ShardKeys (tested). |
| Canary alarm history | `state_dir/alerts.jsonl` (append-only) | Event only, never canary values. |

## GDPR

| Principle or right | Control in tpt-shatter | Status |
|---|---|---|
| Data minimization | Analytics events hold policy-approved fields only, bucketed at ingest | Done (`analytics.rs`, DECISIONS.md) |
| Pseudonymization | Analytics values are bucketed and noised; `pseudonymize()` for keyed identifiers | Done for analytics; salt rotation tooling pending |
| Right to erasure | `erase` deletes by ShardKey across all vaults and reads back to verify (RUNBOOK section 4) | Done for live vaults |
| Erasure from backups | Expiry or tombstone replay on restore | **GAP**: no backups are built |
| Erasure on SSDs and copy-on-write volumes | Key destruction would make fragments unreadable | **GAP**: key destruction is not wired into erasure |
| Storage limitation | Fragments purged after `retention_secs`; analytics events expire with the same window | Done (`purge_expired`, `purge_before`) |
| Accountability | Hash-chained audit of issuance, reads, writes, erasure requests, and alarms | Partial: the caller is recorded as a keyed digest; erasure requests are recorded but have no operator entry point |

## PCI-DSS

| Requirement area | Control in tpt-shatter | Status |
|---|---|---|
| Limit cardholder data storage | Records are split into fragments across vaults by the schema; the schema decides which fields go where | Depends on the deployed schema. Confirm that no vault holds a full PAN before relying on this. |
| Restrict access by need to know | Scoped, short-lived capability tokens (default TTL 60 s); no delete scope issuable | Done |
| Track and monitor access | Audit chain and access log for every authorized read and write | Done; **GAP** caller identity is not in the audit event |
| Protect stored data | ChaCha20-Poly1305 per fragment, with vault label and FragmentId as associated data | Done; key delivery and rotation procedure **GAP** |
| Network segmentation | Vault subnets isolated; gateway and vaults in separate processes | **GAP**: infrastructure (Phase 12) is not built |
| Key management | Keys read from a tmpfs directory (`TPT_KEYS_DIR`) that refuses group- or other-readable files; split custody not implemented | Partial: a KEK split 2-of-3 among custodians (`tpt-shatter-kek`); not audited, and boot-time custody is manual |

PCI-DSS scope depends on the whole cardholder data environment, not on one service, so a
QSA would need to assess the deployed system as a whole.

## HIPAA

| Standard | Control in tpt-shatter | Status |
|---|---|---|
| De-identification of analytics output | Bucketing, noise, and k-anonymity gate | Partial. Safe Harbor requires removing or generalizing each of the 18 listed identifiers for the deployed schema. The code does not check that a schema does this. |
| Access control and audit controls | Capability tokens; audit chain | Partial, as for PCI-DSS |
| Integrity | Audit chain verified on open; AEAD on fragments | Done |
| Contingency plan (backup, DR) | DECISIONS.md describes the plan | **GAP**: no backup or restore tooling; restore drill not run |

The spec's earlier phrasing, "PHI is fragmented" and "de-identified per Safe Harbor", should
not be repeated to an assessor until the schema and the bucketing rules have been checked
against the Safe Harbor list.

## SOC 2

| Criterion | Control in tpt-shatter | Status |
|---|---|---|
| Logical access (CC6) | Capability tokens, mTLS option, rate limits | Partial: mTLS needs certificate provisioning (**GAP**) |
| Monitoring (CC7) | Canary alarms, alert log, Prometheus metrics | Partial: no notification channel (**GAP**); no Grafana alerts (**GAP**) |
| Change management (CC8) | CI: fmt, clippy, tests, cargo-deny, cargo-audit | Done in CI; branch protection is a repository setting outside this code |
| Availability (A1) | Vault breakers, read deadline, health endpoints | Partial: no backups or DR drills (**GAP**) |

## Open items that affect every framework

1. Erasure has no operator entry point. `Node::erase_subject` records the request, but no CLI or service calls it yet.
2. Key rotation, and custody beyond the KEK tool (Phase 11). The KEK tool is not audited.
3. Backup, restore, and erasure of backups (Phase 11 and RUNBOOK section 4).
4. Notification of security staff on canary alarms (Phase 10).
