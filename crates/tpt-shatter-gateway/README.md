# tpt-shatter-gateway

The front door of a tpt-shatter node. The gateway checks a capability token, applies rate limits, reads a record through the assembler, and returns it. Writes go through the same checks and into the shredder. Every outcome is a uniform status and code, so a caller cannot learn why a request was refused beyond what the code says.

The core logic is transport-neutral. [`Gateway::read`](src/service.rs) takes a token and a shard in hex and returns a `Response`. The HTTP/1.1 server and TLS 1.3 layers wrap it.

> **Status:** implemented and tested, including HTTP and TLS integration tests. Not published to crates.io (`publish = false`).

## Contents

- [What it provides](#what-it-provides)
- [Request flow](#request-flow)
- [HTTP API](#http-api)
- [Status and error codes](#status-and-error-codes)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Serving over TLS](#serving-over-tls)
- [Rate limiting](#rate-limiting)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `Gateway::new(signer, source, limiter)` | Builds the gateway from a shared signer, a `RecordSource`, and a per-token `RateLimiter`. |
| `Gateway::read(token, shard_hex, now_ms)` | The transport-neutral read path. Returns a `Response`. |
| `Gateway::with_audit(audit)` | Adds an `AccessAudit` hook. A read the audit cannot record is refused before the fetch. |
| `RecordSource` | Trait that supplies a record for an authorized shard. Implemented by the assembler's adapter, and by any closure with the right signature. |
| `Response` | `status`, `code`, `fields` (on success only), and `token_hash`. `access_log_line()` never includes the token or any value. |
| `Writer`, `RecordSink`, `WriteHandler` | The write path. Requires a `Write` token for the shard. |
| `RateLimiter` | Token bucket per key. Keys are digests, never raw tokens or addresses. |
| `HttpConfig`, `Shared`, `serve`, `serve_tls` | The HTTP/1.1 server and its shared state. |
| `server_config`, `acceptor` | Builds a TLS 1.3 server config, optionally requiring client certificates, and wraps it in an acceptor. |
| `SigningKeyRotator`, `AlarmResponder` | Connects a canary alarm to key rotation and security notification. |
| `ready(breakers_open)` | The readiness rule: ready only when no vault breaker is open. |

## Request flow

For a read:

1. **Rate-limit the source address** (HTTP layer, before anything else, if configured).
2. **Parse the shard** from hex. A malformed shard is `400`.
3. **Verify the token** with the signer, check its shard binding, and check the `Read` scope. Every failure here is the same `401`.
4. **Rate-limit the token.** Over the limit is `429`.
5. **Record the access** with the audit hook. If the record cannot be written, the request stops here.
6. **Fetch** the record through the `RecordSource`. A missing shard is `404`. A vault outage is `503`.
7. **Respond** with the fields and a `200`.

Writes follow the same order with a `Write` scope and the writer in place of the fetch.

## HTTP API

| Method and path | Auth | Purpose | Success |
| --- | --- | --- | --- |
| `GET /healthz` | none | Liveness. Always answers. | `200 {"status":"live"}` |
| `GET /readyz` | none | Readiness. Fails while any vault breaker is open. | `200 {"status":"ready"}` |
| `GET /v1/records/{shard_hex}` | `Authorization: Bearer <token>` | Read a record. | `200 {"fields":{...}}` |
| `PUT /v1/records/{shard_hex}` | `Authorization: Bearer <token>` | Write a record. Body: `{"fields":{"name":"value",...}}`, string values only. | `201 {"status":"created"}` |

Every response is JSON with `Cache-Control: no-store`. Errors are `{"error": "<code>"}`. The token travels only in the `Authorization` header, never in the URL or the body.

The write route is only offered when a writer is configured. Without one, `PUT` returns `405`. The request body is capped at 64 KiB.

## Status and error codes

| Status | Code | When |
| --- | --- | --- |
| 200 | `ok` | Read succeeded. |
| 201 | `created` | Write succeeded. |
| 400 | `bad_request` | Malformed shard, malformed body, duplicate field, or a field outside the schema. |
| 401 | `unauthorized` | Forged, expired, wrong-shard, or wrong-scope token. These look identical on purpose. |
| 404 | `not_found` | No such shard, or the shard has been erased. Also any unknown route. |
| 405 | `method_not_allowed` | Wrong method, or a write when no writer is configured. |
| 413 | `too_large` | Write body over 64 KiB. |
| 429 | `rate_limited` | Token or source address is over its limit. |
| 500 | `internal` | Unexpected internal failure. |
| 503 | `unavailable` | A vault is unavailable. Also `timeout` when the request exceeds `request_timeout`, and `not_ready` from `/readyz`. |

Token failures are deliberately uniform, so a caller cannot tell a forgery from an expiry or a wrong scope.

## Installation

```toml
[dependencies]
tpt-shatter-gateway = { path = "../tpt-shatter-gateway" }
```

## Quick start

```rust
use std::sync::{Arc, RwLock};
use tpt_shatter_gateway::{Gateway, RateLimiter};

let signer = Arc::new(RwLock::new(signer));
let limiter = RateLimiter::new(10, 5, 10_000)?; // burst 10, 5 per second, up to 10k tokens tracked
let gateway = Gateway::new(Arc::clone(&signer), source, limiter);

let response = gateway.read(token, shard_hex, now_ms);
println!("{} {}", response.status, response.code);
```

Any closure of type `Fn(&ShardKey) -> Result<Record, ShatterError>` is a `RecordSource`, which makes tests and small services easy to write.

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`read_path`](examples/read_path.rs) | The transport-neutral read path: a valid token, wrong shard, forgery, expiry, and a burst that hits the rate limit. | `cargo run -p tpt-shatter-gateway --example read_path` |
| [`http_server`](examples/http_server.rs) | Serving the gateway over HTTP on a local port, then making authorized and anonymous requests to it with a raw socket. | `cargo run -p tpt-shatter-gateway --example http_server` |

## Serving over TLS

Production serves TLS 1.3 only. Build the server config from a PEM certificate chain and key, then pass the acceptor to `serve_tls`:

```rust
use tpt_shatter_gateway::{acceptor, server_config, serve_tls};

let config = server_config(&cert_pem, &key_pem, None)?;          // TLS 1.3 only
// For mutual TLS, pass the client CA: server_config(&cert_pem, &key_pem, Some(&client_ca_pem))?
let tls = acceptor(config);
serve_tls(listener, shared, tls).await?;
```

Client certificates are optional. When a client CA is given, the server requires a certificate that chains to it. The TLS provider is `rustls` with the pure-Rust graviola backend. `ring` and `aws-lc-rs` are not used, because both carry Apache-only components; [DECISIONS.md](../../DECISIONS.md) records the reasoning.

Plain HTTP exists for local development. The node refuses to start without TLS unless `allow_plain_http` is set.

## Rate limiting

`RateLimiter` is a token bucket per key. Each key holds up to `capacity` requests and refills at `refill_per_sec`.

- **Per token.** The read path keys the limiter by a digest of the token. The raw token is never stored.
- **Per source address.** The HTTP layer can apply a second limiter to `/v1/records` before the token is checked. This stops a flood of bad tokens from consuming the per-token budget of anyone else.
- **Bounded memory.** The table holds at most `max_keys` keys. Idle buckets are pruned first. If the table is still full, new keys are refused. This is fail closed: a flood of distinct keys cannot grow memory without limit.

Probes (`/healthz`, `/readyz`) are not rate limited.

## Security properties

- **Uniform token failures.** Forgery, expiry, wrong shard, and wrong scope all return the same `401`.
- **Uniform not-found.** A shard that is absent and a shard that was erased look the same to the caller.
- **No secrets in logs.** Access-log lines carry the status, code, a hash of the token, and a field count. Never the token, a field value, or a shard key.
- **Audit before access.** If the audit hook cannot record an access, the fetch does not run.
- **No token in URLs.** The token is read from the `Authorization` header only.
- **Responses are not cached.** Every response carries `Cache-Control: no-store`.
- **Canary response wired in.** `AlarmResponder` rotates the signing key on a canary alarm, which invalidates all outstanding tokens.

## Limitations

- **Plain HTTP has no confidentiality.** Use TLS in any environment that carries real data.
- **The gateway does not decide who may hold a token.** Token issuance is the issuer's job (see the [node](../tpt-shatter-node/)). The gateway only checks what a token says.
- **Rate limits are per process.** Several gateway processes each keep their own limits. A shared limiter would need external state.
- **Requests are synchronous behind the scenes.** `Gateway::read` is blocking, so the HTTP layer runs it on the blocking pool. A slow vault uses one blocking thread for the duration of the request, bounded by `request_timeout`.
- **No gRPC transport.** The project dropped gRPC in favor of HTTP/1.1. See `DECISIONS.md` at the repository root.

## Testing

```sh
cargo test -p tpt-shatter-gateway
```

The unit tests cover every token failure looking the same, valid reads, wrong shards, malformed shards, missing records, vault outages, per-token rate limits, key rotation, alarm notifications, readiness, access-log contents, and the write path's scope rules and body limits. The HTTP tests cover the route table, probes, source limits, oversized heads, and write bounds. The TLS tests in [`tests/tls.rs`](tests/tls.rs) run a real TLS 1.3 handshake against the test fixtures, with and without a client certificate.

The fixtures in `tests/fixtures/` are test-only keys and certificates. They must never be used in a deployment.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
