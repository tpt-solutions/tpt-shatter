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
