# Changelog

All notable changes to `tpt-shatter-gateway-service` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `tpt-shatter-gateway` binary: the public read path as its own process, from a JSON config with unknown fields refused. It checks tokens, applies per-token and per-source rate limits, records each authorized read on its own audit chain, and fetches records from the assembler service over mTLS.
- `GatewayConfig`, which refuses to start unless `acknowledge_canary_gap` is `true`. Canary alarms do not revoke tokens on a separate gateway yet.
- `GatewayAudit`: an `AccessAudit` that records reads under the gateway's own key. Writes are refused before anything is recorded.
- End-to-end tests over loopback TLS: a token reads a record through the gateway and the assembler, unauthenticated and wrong-shard requests are refused, the audit chain verifies under the gateway's key and not the node's, and the config refusals hold.
- Alarm listener (`alarm` config): accepts `POST /v1/alarm` over mTLS from a client certificate chaining to `client_ca`. It installs a rotation only when the version is newer than the installed one, and answers `409` otherwise. The rotation is written to the gateway's audit chain before the key changes, so a rotation that cannot be recorded does not happen.
- `serve_alarms`, the listener's server, with the same connection limit and timeouts as the other services.
- End-to-end tests over loopback TLS: a pushed key revokes old tokens and enables new ones, stale versions are refused, a peer without the node's certificate cannot rotate, and an alarm listener replaces the canary acknowledgement.

### Changed
- `acknowledge_canary_gap` is needed only when no alarm listener is configured. The test helpers moved to `tests/common`.
