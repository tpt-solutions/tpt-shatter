# Operations Runbook (draft)

**Status: draft.** This project has no deployable binary yet. The procedures below describe
what the library code does today, and where a step needs code or infrastructure that
does not exist yet, it is marked **GAP**. Do not follow a GAP step as if it were
automated. Review this runbook before any deployment.

## 1. Deploy

- **GAP:** there is no service binary. Each service (gateway, shredder, assembler, emitter,
  canary) needs a `main` that wires the library pieces together.
- **GAP:** container build is not set up (Distroless, static musl). See the Phase 12 items.
- Before any deploy, confirm the dependency policy: `cargo deny check` must pass
  (`deny.toml`). The TLS provider is pinned to `rustls-graviola =0.2.1`. Do not upgrade it
  without re-running the check.
- Configure TLS for the gateway through `tpt_shatter_gateway::server_config` and serve
  with `serve_tls`. Use TLS 1.3. Enable mTLS by passing the client CA.
- Vault connections must use TLS and SCRAM-SHA-256. Keystone enables these only when
  roles are populated or `TPT_TLS_CERT_PATH` / `TPT_TLS_KEY_PATH` are set (see
  `UPSTREAM.md`). **GAP:** the vault client does not yet open TLS connections.

## 2. Keys

- **Token signing key.** Held in gateway RAM. Rotation is `SigningKeyRotator`, which
  invalidates every outstanding token at once. **GAP:** there is no key-delivery
  mechanism yet. Keys must be delivered RAM-only at boot (see DECISIONS.md, Keys).
- **Derivation key** (FragmentId). Must never be persisted by the shredder, the
  assembler, or the vault. **GAP:** provisioning is not built.
- **Canary key.** Derived per epoch with `CanaryPlan::for_epoch` from a master key. The
  epoch length is 7 days (`epoch_at`).
- **Audit chain key.** Separate from every data key. **GAP:** key storage is not built.

## 3. Canary alarm response

When the canary detects a canary FragmentId in a vault query log:

1. **Automatic:** `AlarmGate::handle` rotates the signing key and invalidates all
   tokens. The gate then disarms, so repeated hits do not rotate again.
2. **Automatic:** `Responder::notify_security` is called for each alarm. **GAP:** the
   notification channel (webhook, email, or pager) is not wired. Until it is, check the
   alarm events in the audit chain yourself.
3. **Operator:** verify the audit chain with `verify_chain`. If the chain fails, treat
   the audit log as altered and escalate.
4. **Operator:** identify the query that touched the canary. **GAP:** the canary cannot
   yet tail query logs. Keystone's audit table `_mirror_audit` is readable by polling,
   and it is not confirmed to record query text (see `UPSTREAM.md`).
5. **Operator:** re-arm only after the cooldown. `AlarmGate::rearm` refuses to re-arm
   before the cooldown ends. Re-arming is a human decision, not an automatic one.

## 4. Erasure (GDPR)

1. Obtain the ShardKey for the data subject. Erasure is by ShardKey, which derives the
   FragmentIds.
2. Call `erase(router, derivation_key, shard)`. It deletes in every vault and then reads
   back to verify. The call is idempotent, so repeat it on any error.
3. If `EraseReport::verified` is false, repeat the call and escalate if it stays false.
4. **GAP:** backups. Erased subjects must be removed from backups by expiry or by
   replaying tombstones on restore. This is not yet built.

## 5. Orphan fragments

- A failed write is compensated by deleting the fragments already written. If that
  compensating delete also fails, the fragment is queued as an orphan.
- Call `Shredder::reap(max_attempts)` on a schedule. Check the `ReapReport`:
  `abandoned` counts orphans given up on, and each one needs an operator.
- Use `Shredder::with_orphan_log` so the queue survives a restart. Without a log path,
  the queue is RAM-only and a restart loses it.
- **GAP:** the schedule is not automated. Run a reap pass on a timer until that exists.
- After a reap with `abandoned > 0`, escalate. Abandoned orphans are dropped from the
  queue, and the queue holds only FragmentIds. Finding or deleting those rows by hand needs
  the ShardKey, which the queue never stores. **GAP:** there is no abandonment alarm yet.

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

- Keep the audit chain head outside keystone, as an anchor (see DECISIONS.md, Audit
  anchoring). **GAP:** anchoring is not implemented yet.
- Keep `cargo deny` output and test output for each release.
