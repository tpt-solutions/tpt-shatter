# Operations Runbook (draft)

**Status: draft.** There is one process binary, `tpt-shatter-node`, which runs the read
path, the orphan reaper, and the canary monitor. Where a step needs code or infrastructure
that does not exist yet, it is marked **GAP**. Do not follow a GAP step as if it were
automated. Review this runbook before any deployment.

## 1. Deploy

- Run `tpt-shatter-node <config.json>`. The config is JSON with `deny_unknown_fields`:
  `listen`, `tls_cert`, `tls_key`, optional `client_ca` (turns on mTLS), `schema`,
  `state_dir`, `vault_dirs` (`a`, `b`, `c`) or `remote_vaults` (see below), `canary_count`,
  `canary_period_secs`,
  `alarm_cooldown_secs`, `reap_interval_secs`, `reap_max_attempts`,
  `monitor_interval_secs`, `retention_secs` (maximum fragment age; at least
  `canary_period_secs`), `purge_interval_secs`. `allow_plain_http` is for development only, and TLS is required
  by default. The binary refuses to start without TLS settings.
- Vaults can run as separate services. Each vault runs `tpt-shatter-vault <config.json>` on
  its own host, with its own key file and directory, and requires node client certificates
  that chain to its `client_ca`. The node then sets `remote_vaults` (`a`, `b`, `c` as
  `host:port`, `server_name`, `ca`, `client_cert`, `client_key`) in place of `vault_dirs`, and
  holds no vault keys. Each vault service runs its own retention purge (`retention_secs`,
  `purge_interval_secs`). The protocol is in `crates/tpt-shatter-vault-service/README.md`.
  **GAP:** the services are not deployed by any Terraform or Kubernetes config yet.
- Production: set `TPT_KEYS_DIR` to a directory on a tmpfs holding one file per key, named
  as below, each with 64 hex characters and mode 0400. The node refuses a key file that is
  readable or writable by group or others. The boot step writes the directory from the
  sealed key material, through the custody ceremony in the next section.
- Key custody ceremony (`tpt-shatter-kek`, see its README). Run it on a trusted machine,
  not on a node.
  1. `generate <dir> <names...>` writes fresh keys, or `<dir>` already holds the keys to
     protect.
  2. `seal <dir> <blob>` writes the blob and prints three custodian shares. Give each share
     to a different custodian, in a sealed envelope, and record which custodian holds which
     share. Shares must not be photographed, emailed, or stored with the blob.
  3. Delete `<dir>` with a secure overwrite. The blob may be stored with the node.
  4. Boot: on the node, run `unseal <blob> /run/tpt-keys` with two shares on stdin, then start
     the node with `TPT_KEYS_DIR=/run/tpt-keys`. `/run` must be a tmpfs. Two custodians must
     be present for every boot.
  5. To change a key, repeat from step 1 with the new key, then re-seal. Re-keying the
     derivation key is a re-shatter, not a rotation (see DECISIONS.md).
  **GAP:** no tool checks that `/run` is a tmpfs, and the shares are typed at a terminal.
- Cloud custody, instead of shares: `seal <dir> <blob> --kms-wrap <program>`, and at boot
  `unseal <blob> /run/tpt-keys --kms-unwrap <program>`. The program is an operator-written
  wrapper: it reads hex on stdin, calls the cloud KMS to encrypt or decrypt, and prints hex on
  stdout. Cloud CLIs usually emit base64, so the wrapper converts. The path to the program is
  fixed in the boot unit file, not read from the blob. Boot then needs no custodians, only the
  cloud identity the wrapper runs as, so restrict that identity to the one KMS key.
  **Not tested against a live cloud KMS.**
- Development only: keys come from the environment, as 64 hex characters each: `TPT_KEY_VAULT_A`,
  `TPT_KEY_VAULT_B`, `TPT_KEY_VAULT_C`, `TPT_KEY_DERIVATION`, `TPT_KEY_TOKEN`,
  `TPT_KEY_CANARY_MASTER`, `TPT_KEY_AUDIT`, `TPT_KEY_ANALYTICS`. The binary names the variable that failed and never prints a
  value. The key directory is filled by `tpt-shatter-kek unseal`, which is manual.
- On start, the node writes the current epoch's canaries into the vaults and records the
  epoch in `state_dir/canary_epoch`. Each monitor pass refreshes canaries when the epoch
  changes, runs the canary response, and writes alarms to `state_dir/alerts.jsonl`.
- Records are written with `PUT /v1/records/{shard_hex}`, a JSON body
  `{"fields": {name: string}}` up to 64 KiB, and a token with the `Write` scope for that
  shard. Success is `201`. Unknown field names are `400`, and an oversized body is `413`.
  Writes and reads share one orphan queue, so reaping and ingestion agree.
- Tokens come from the issuer, when the config has an `issuer` section. It listens on its
  own address (`issuer.listen`, keep it on an internal network) with the same TLS rules. A
  caller sends `POST /v1/tokens` with `Authorization: Bearer <secret>` and a JSON body
  `{"shard": hex, "scopes": ["read"|"write"], "ttl_secs": n}`. `ttl_secs` is optional, and
  defaults to 60. The response is `201` with `token` and `expires_at`.
- Each caller in `issuer.callers` has `name`, `secret_sha256` (SHA-256 of the caller's
  secret, as 64 hex characters), `scopes`, and `max_ttl_secs`. The config never holds the
  secret itself. Create a secret with at least 32 random bytes and store only its hash.
- Refusals: `401` for a wrong or missing secret, `403` for a scope or TTL the caller may
  not use, and `400` for a malformed request. `delete` is never issuable, since erasure is
  maintenance. A token that cannot be recorded in the audit log is withheld (`500`).
- The audit log is `state_dir/audit.jsonl`. It is a keyed hash chain, sealed with
  `TPT_KEY_AUDIT`. The node refuses to start if the log does not verify under that key, so
  keep the key and the log together. The log holds digests and times, not tokens, secrets,
  or field values.
- To export a compliance summary, run `tpt-shatter-node export-audit <config.json>`. It
  verifies the chain first and prints counts by action and vault, the time range, and the
  head MAC, with no digests. See [COMPLIANCE.md](COMPLIANCE.md).
- The audit event records the caller as a keyed digest of the caller tag, which the token
  carries (token version 2). Version 1 tokens are refused.
- The issuer listener uses the node's TLS acceptor. When `client_ca` is set, it requires
  client certificates too, so mTLS applies to both listeners. Without `client_ca`, caller
  secrets are the only caller authentication. Either way, keep the issuer address on an
  internal network.
- **GAP:** no container image is built, and the process is not yet run under a supervisor.
- **GAP:** no multi-process coordination exists for a vault directory. Run one node per
  vault directory.
- Run `tpt-shatter-node` once with `reap_interval_secs` and `monitor_interval_secs` small
  in a test environment before relying on the timers.
- **GAP:** container build is not set up (Distroless, static musl). See the Phase 12 items.
- Before any deploy, confirm the dependency policy: `cargo deny check` must pass
  (`deny.toml`). The TLS provider is pinned to `rustls-graviola =0.2.1`. Do not upgrade it
  without re-running the check.
- Configure TLS for the gateway through `tpt_shatter_gateway::server_config` and serve
  with `serve_tls`. Use TLS 1.3. Enable mTLS by passing the client CA.
- Vaults are local `FileVault` directories, one per vault, each on its own volume with its
  own sealing key. No vault network connection exists, so no vault TLS or SCRAM setup is
  needed. **GAP:** the vault key delivery and volume layout are not built.

## 2. Keys

- **Token signing key.** Held in gateway RAM. Rotation is `SigningKeyRotator`, which
  invalidates every outstanding token at once. The node pushes the new key to each gateway's
  alarm listener before it switches, so a canary alarm reaches every gateway. Rotation is not
  durable: after a restart, the node and the gateways reload keys from provisioning, so restart
  them from the same key set. A gateway that restarts alone fails closed. **GAP:** there is no key-delivery
  mechanism yet. Keys must be delivered RAM-only at boot (see DECISIONS.md, Keys).
- **Derivation key** (FragmentId). Must never be persisted by the shredder, the
  assembler, or the vault. **GAP:** provisioning is not built.
- **Canary key.** Derived per epoch with `CanaryPlan::for_epoch` from a master key. The
  epoch length is 7 days (`epoch_at`).
- **Audit chain key.** Separate from every data key. **GAP:** key storage is not built.

## 3. Canary alarm response

When the canary detects a canary FragmentId being read through the vault router:

1. **Automatic:** `AlarmGate::handle` rotates the signing key and invalidates all
   tokens. The new key is pushed to every gateway alarm listener before this node switches.
   If a push fails, the node keeps its old key and the gate stays armed, and the next monitor
   pass retries. The gate disarms once the rotation completes, so repeated hits do not rotate
   again.
2. **Automatic:** `Responder::notify_security` is called for each alarm. The alert log
   (`AlertLog`, written by `Alarm::record`) is the channel. **GAP:** a pager or SIEM does
   not tail that file yet, and webhook and email delivery are not built. Until they are,
   read the file yourself, and check the alarm events in the audit chain.
3. **Operator:** verify the audit chain with `verify_chain`. If the chain fails, treat
   the audit log as altered and escalate.
4. **Operator:** identify the caller that touched the canary. The alarm holds the vault and
   canary index only. Detection runs in the router (`Router::with_observer` and
   `CanaryWatch`). A hit means a read or delete through the router, which is the only path
   our services use. Maintenance paths (erasure, rotation, reaping) are not observed by
   design. Direct access to a vault's files on the host is not detected at all.
   The response runs through `CanaryMonitor::poll`, on the node's monitor loop.
5. **Operator:** re-arm only after the cooldown. `AlarmGate::rearm` refuses to re-arm
   before the cooldown ends. Re-arming is a human decision, not an automatic one.
6. **Split assembler.** A canary read through `tpt-shatter-assembler` is seen by its own
   `CanaryWatcher`, not by the node. The first hit locks the assembler, and every read is
   refused until the assembler is restarted, so the gateway also stops serving reads. The
   restart is the re-arm step: read the `alert_log` file named in the assembler's config first. The
   lock does not rotate the token key. **GAP:** the node's canary list
   (`state_dir/canary-ids.txt`) must be copied to the assembler host by hand. The assembler
   refuses to start without it. If the list goes stale, the assembler logs
   `canary_list_stale` and keeps serving, so treat that entry as a node fault: the node has
   stopped refreshing its canaries.

## 4. Erasure (GDPR)

1. Obtain the ShardKey for the data subject. Erasure is by ShardKey, which derives the
   FragmentIds.
2. Call `erase(router, derivation_key, shard)`. It deletes in every vault and then reads
   back to verify. The call is idempotent, so repeat it on any error.
3. If `EraseReport::verified` is false, repeat the call and escalate if it stays false.
4. **GAP:** backups. Erased subjects must be removed from backups by expiry or by
   replaying tombstones on restore. This is not yet built.
5. **GAP:** overwrite erasure is not guaranteed on SSDs with wear leveling or on
   copy-on-write file systems. The fallback is destroying the vault key, which makes every
   fragment file unreadable. Key destruction is not wired into erasure yet.

## 5. Orphan fragments

- A failed write is compensated by deleting the fragments already written. If that
  compensating delete also fails, the fragment is queued as an orphan.
- Call `Shredder::reap(max_attempts)` on a schedule. Check the `ReapReport`:
  `abandoned` counts orphans given up on, and each one needs an operator.
- Use `Shredder::with_orphan_log` so the queue survives a restart. Without a log path,
  the queue is RAM-only and a restart loses it.
- Run `run_reaper` on a dedicated thread with a stop flag. It reaps on an interval and
  calls a callback after each pass. **GAP:** no service runs it yet.
- After a reap with `abandoned > 0`, escalate. Abandoned orphans are dropped from the
  queue, and the queue holds only FragmentIds. Finding or deleting those rows by hand needs
  the ShardKey, which the queue never stores.
- The `run_reaper` callback receives each pass's report, so it can raise the alarm. The
  alert log (`AlertLog`, a `reap_abandoned` line) receives it when `run_reaper` is given
  one. **GAP:** nothing tails that file yet.

## 6. Analytics

- The durable copy of anonymized events is the JSON-lines file written by
  `JsonlSink`. Back it up. Strata is rebuilt from it with `JsonlSink::read_all`.
- **GAP:** strata's persistence and recovery are undocumented upstream, so do not treat
  strata as durable.

## 7. Disaster recovery

- **GAP:** no DR procedure is implemented or drilled. See DECISIONS.md for the target:
  per-vault encrypted backups, RPO 24 h, RTO 4 h, quarterly restore drills, and a 2-of-3
  split of key custody.
- Until a drill has been run, treat the RPO and RTO as untested targets.

## 8. Evidence to keep

- Keep the audit chain's head hash on a volume other than the vault volumes, so a vault
  compromise cannot rewrite both. **GAP:** anchoring is not implemented yet.
- Keep `cargo deny` output and test output for each release.

## Analytics export (BI)

- `tpt-shatter-node export-analytics <config.json> <group> [value]` writes a CSV to stdout:
  a count of each `group` value, or the sum of `value` per group when `value` is given.
- It reads `state_dir/analytics.jsonl` only. It never writes the log, so it is safe while the
  node runs.
- Only events inside `retention_secs` count. Groups with fewer than the policy's `k` events
  are left out, because a small cohort could identify the people in it.
- A field that starts with `=`, `+`, `-`, or `@` is prefixed with `'` so a spreadsheet reads
  it as text.
- Sums are noisy by design, since the `balance`-style fields pass through the policy's noise
  transform. Treat them as estimates.
- **Scheduled exports.** Set `analytics.export_dir` and `analytics.exports` in the node config, for
  example `{"group": "birth_year", "file": "by_decade.csv"}` or `{"group": "birth_year", "value":
  "balance", "file": "balance_by_decade.csv"}`. The node rewrites each file every
  `analytics.export_interval_secs` (default 3600). Files are written beside their name and renamed
  into place, so a reader never sees a partial file. The BI tool reads files from `export_dir`.
- **Delivery is not built.** Copying `export_dir` to a BI tool, and the analytics subnet that would
  carry it, are infrastructure work (Phase 12). Nothing here opens a network path.

## Metrics

- Set `metrics_listen` to an address on the management network, for example `10.0.0.5:9100`.
  The endpoint is off when the key is absent. It uses the node's TLS settings.
- `GET /metrics` returns Prometheus text. Other paths get `404`.
- Series: `tpt_shatter_access_total{status,code}`, `tpt_shatter_canary_alarms_total`,
  `tpt_shatter_analytics_emitted_total`, `tpt_shatter_fragments_purged_total`,
  `tpt_shatter_vault_breaker_open{vault}`, `tpt_shatter_vault_consecutive_failures{vault}`, and
  the `tpt_shatter_assembly_seconds` histogram.
- OTLP export is handled by an OpenTelemetry Collector beside each node. The Collector scrapes
  `/metrics` and reads the node's stdout logs. Its configuration is Phase 12 work.
- **GAP:** no Collector configuration, dashboards, or alert rules are provided yet.
