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

- Without an `alarm` listener, `acknowledge_canary_gap` must be `true`. With one, the flag is not
  needed. Without the listener, a canary alarm on the node rotates only the node's key, and
  tokens minted before the alarm still verify here.
- Unknown config fields, a zero assembler timeout, and any unreadable or badly permissioned
  key file stop the process before it listens.

## Canary alarms

The node pushes a new token signing key to this gateway's alarm listener when its canary
monitor fires. The listener requires a client certificate that chains to `alarm.client_ca`.
It installs the key only when the version is newer than the current one, and writes the
rotation to the audit chain first. Keep the listener on the management network.

## Known gaps

- Readiness (`/readyz`) reports only that the process is up. Assembler health is not part
  of it.
- A restart reloads the token key from provisioning. A gateway that restarts without its node
  disagrees with it on the key, and fails closed until both are reloaded from the same key set.
- Canary reads made through the assembler service are not detected. See DECISIONS.md.
- The token key is shared with the node's issuer, so compromising this host forges tokens
  for the key's lifetime. That is the spec's stated limit on the token key (7.2).
