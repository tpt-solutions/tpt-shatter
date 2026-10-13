# Security review: token and assembler crates

Scope: `tpt-shatter-token` (`lib.rs`: issue, verify, shard and scope checks) and
`tpt-shatter-assembler` (`lib.rs`: fetch, deadline path, record build), plus the in-flight
guard in `tpt-shatter-vault-client` that the assembler's fetches go through.

Not reviewed: `migrate.rs`, `codec.rs`, `file_vault.rs` internals, and the HTTP parser.
This is one reviewer's pass, not an independent audit. Fuzzing is still pending.

## Fixed

1. **Stalled vault could exhaust threads (availability, medium).** The deadline path
   spawns one thread per vault per read. A stalled call never returns, so the breaker never
   records a failure and never opens. Threads then grow with the request rate until memory
   runs out. **Fix:** `BreakerConfig::max_in_flight` (default 64 per vault). A call over the cap
   fails at once with `VaultUnavailable`. The slot is freed by a drop guard, so a panicking
   backend cannot leak it. Tested: two stalled calls hold both slots, a third is refused,
   and the slots are released after the stalled calls return.

## Accepted by design (documented in `tpt-shatter-token`)

2. **Tokens are replayable for up to 60 seconds** against their bound shard and scopes. A
   nonce store would make validation stateful. Key rotation invalidates every token at once.
3. **The raw shard key travels in the token.** Holding a token means holding the routing key
   for at most 60 seconds. Vault access still needs the derivation key, which the token
   never carries.

## Fixed or documented, low severity

4. **Key bytes are passed by value** to `Signer::new` and `Signer::rotate`, so stack copies of
   `[u8; 32]` are not zeroized. Accepted: the keys already live as plain arrays in `Keys`,
   which `parse_key` fills, so changing the constructor would not remove the copies. Zeroizing
   the keys end to end is a larger change, and it is not justified by this finding alone.
5. **`Assembler::assemble` has no deadline.** Documented as such. The node uses
   `assemble_with_deadline`. The unbounded path stays for migration and tests.
6. **Stalls do not trip the breaker.** Bounded by the in-flight cap, and now visible: the
   `tpt_shatter_vault_in_flight` gauge reports calls in flight per vault.
7. **Existence is visible to token holders.** A valid token for a missing shard gets `404`,
   and a valid token for a present shard gets `200`. Anyone holding a valid token already
   knows the shard, so this reveals nothing new. Noted for completeness.

## Checked and found correct

- Token verification checks the MAC before it trusts any field. Comparisons are constant-time,
  and the shard check uses `ct_eq`.
- Expiry is checked after the MAC, so an attacker cannot tell forged from expired by timing.
- Decoded field values are `Zeroizing`, so reconstructed plaintext is wiped when the
  intermediate values are dropped. The `Record` type is `ZeroizeOnDrop`.
- Every partial-fetch condition (missing, duplicate, misplaced, wrong schema version) fails
  the whole build. No partial record is returned.
- Vault errors reach clients as a generic `503`, without naming the vault.
