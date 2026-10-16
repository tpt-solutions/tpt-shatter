# Changelog

All notable changes to `tpt-shatter-assembler-service` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `tpt-shatter-assembler` binary: serves the assembler over mTLS from a JSON config with unknown fields refused. It loads the derivation key from a mode-checked file, builds three remote vault clients behind circuit breakers, and requires a gateway client certificate.
- `AssemblerSource`: reassembly with a read deadline, using `assemble_with_deadline`.
- `serve`: the HTTP/1.1 server for `GET /v1/records/{shard_hex}`. Responses are `{"fields": {...}}`, or an error code with the vault label. Requests that cannot be parsed get `400`.
- End-to-end tests over loopback mTLS: a record shredded into three vault services is read back through `RemoteAssembler`. Also covered: a shard with no fragments, a client without a certificate (refused), and an unreachable assembler (`ServiceUnavailable`).
- Canary detection on the assembler: `CanaryWatcher` watches the router for canary reads
  using the node's canary ID list, so this host holds no canary key. The first canary read
  locks the source, and a locked source refuses reads until restart (`LockedSource`). A list
  that is unreadable, malformed, or from an older epoch is refused and logged.
- `canary_ids_file`, `alert_log`, and `monitor_interval_secs` in the binary's config.
  `canary_ids_file` and `alert_log` are required, and the binary refuses to start without a
  readable canary list.
- Stale canary lists are logged as `canary_list_stale` once per stale stretch. The check uses
  the new required `canary_period_secs` (must match the node) and `canary_stale_grace_secs`
  (default 600). Serving continues.
- `canary_push` (optional): a second mTLS listener that accepts the node's canary list at
  `POST /v1/canary-ids`, with its own client CA. It refuses a list older than the one on disk.
- An assembler with no canary list yet starts awaiting the node's first push. It refuses reads
  until a list arrives. `ReadGate` tracks this separately from the alarm lock. A list that is
  present but unreadable still stops startup.
