# tpt-shatter-assembler-service

Runs the assembler as its own service, so the gateway can run on a separate host.

- `tpt-shatter-assembler` (binary): reads a JSON config, builds three remote vault clients,
  loads the derivation key (mode-checked), and serves reassembly over mTLS. It refuses to
  start without a readable canary ID list.
- `AssemblerSource`: the reassembly step, with a deadline.
- `serve`: the HTTP/1.1 server. It accepts `GET /v1/records/{shard_hex}` from clients that
  present a certificate chaining to `client_ca`, and answers with `{"fields": {...}}` or an
  error code.
- `CanaryWatcher` and `LockedSource` (`canary` module): watch the assembler's own router for
  canary reads, using the list the node writes. The first canary read locks the source, and
  a locked assembler refuses every read until it is restarted.

The client side is `tpt_shatter_gateway::RemoteAssembler`. The gateway needs no vault
client and no derivation key. See `infrastructure/README.md` for where this runs.

Known gaps: the node's canary ID list must be copied to this host by something outside this
crate. A stale list is logged as `canary_list_stale`, not locked. A canary alarm here locks reads but
does not rotate the token key, because this host holds no signing key. See DECISIONS.md,
canary detection on the assembler.
