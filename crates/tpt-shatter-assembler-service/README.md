# tpt-shatter-assembler-service

Runs the assembler as its own service, so the gateway can run on a separate host.

- `tpt-shatter-assembler` (binary): reads a JSON config, builds three remote vault clients,
  loads the derivation key (mode-checked), and serves reassembly over mTLS.
- `AssemblerSource`: the reassembly step, with a deadline.
- `serve`: the HTTP/1.1 server. It accepts `GET /v1/records/{shard_hex}` from clients that
  present a certificate chaining to `client_ca`, and answers with `{"fields": {...}}` or an
  error code.

The client side is `tpt_shatter_gateway::RemoteAssembler`. The gateway needs no vault
client and no derivation key. See `infrastructure/README.md` for where this runs.

Known gap: canary alarms are not observed here yet. The router's observer, which the node
uses for canary detection, is not attached in this binary, and the alarm response (rotating
the gateway's token key) cannot reach a gateway on another host.
