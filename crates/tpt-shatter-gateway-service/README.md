# tpt-shatter-gateway-service

The public read path as its own process.

- `tpt-shatter-gateway` (binary): reads a JSON config, loads the token key and the gateway's
  own audit key (mode-checked files), and serves `GET /v1/records/{shard_hex}` over TLS 1.3.
  Clients present `Authorization: Bearer <token>`. Records come from the assembler service
  over mTLS, through `RemoteAssembler`.
- `GatewayAudit`: records each authorized read on the gateway's own chain, in
  `state_dir/gateway-audit.jsonl`, under `audit_key_file`. The node's audit key is not used
  here, so the node's chain cannot be read or written from this host.

What this process does not hold: the derivation key, any vault key, and any vault client.
Its dependency tree has no vault, assembler, shredder, or canary crates.

Writes are not served here. They stay on the node's ingestion path.

## Refusals at startup

- `acknowledge_canary_gap` must be `true`. Canary alarms are raised by the node, and its
  response rotates the node's signing key only. A token minted before the alarm still
  verifies here, so a canary read does not revoke it. Set the flag only once that is
  accepted.
- Unknown config fields, a zero assembler timeout, and any unreadable or badly permissioned
  key file stop the process before it listens.

## Known gaps

- Readiness (`/readyz`) reports only that the process is up. Assembler health is not part
  of it.
- The token key is shared with the node's issuer, so compromising this host forges tokens
  for the key's lifetime. That is the spec's stated limit on the token key (7.2).
