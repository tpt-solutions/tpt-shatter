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
