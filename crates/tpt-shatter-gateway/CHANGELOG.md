# Changelog

All notable changes to `tpt-shatter-gateway` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Gateway::read`, the transport-neutral read path: source parsing, token verification with shard and scope checks, per-token rate limiting, audit hook, fetch, and uniform error mapping.
- `Response` with a stable status and code for every outcome, and `access_log_line` that never includes secrets.
- `RecordSource` trait, implemented for closures.
- Write path (`Writer`, `RecordSink`) requiring a `Write` token, with a 64 KiB body cap.
- HTTP/1.1 server (`serve`, `serve_tls`) with `/healthz`, `/readyz`, `GET` and `PUT /v1/records/{shard}`, `Cache-Control: no-store`, a request timeout, and an optional per-source limiter.
- TLS 1.3 configuration (`server_config`, `acceptor`) with optional mutual TLS, using the graviola provider.
- `RateLimiter`, a bounded token bucket keyed by digest, failing closed when full.
- `SigningKeyRotator` and `AlarmResponder`, connecting canary alarms to key rotation and security notification.

### Changed
- The gRPC transport was dropped in favor of HTTP/1.1. See `DECISIONS.md`.
