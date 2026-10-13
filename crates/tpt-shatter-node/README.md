# tpt-shatter-node

The process that runs a tpt-shatter deployment. It opens the three vaults, wires the router, shredder, assembler, canaries, gateway, and token issuer together, and runs the background work: canary refresh and alarm response, orphan reaping, and retention purges.

The crate is both a library and a binary. The binary, `tpt-shatter-node`, runs one node from a JSON configuration file. The library exposes the same wiring, so tests and tools can build a node in-process.

> **Status:** implemented and tested, including end-to-end tests that write a record through the node and read it back through the gateway. Not published to crates.io (`publish = false`).

## Contents

- [What it provides](#what-it-provides)
- [What a running node does](#what-a-running-node-does)
- [Installation and running](#installation-and-running)
- [Configuration](#configuration)
- [Keys](#keys)
- [Token issuer](#token-issuer)
- [Audit](#audit)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `Config`, `VaultDirs`, `CallerConfig`, `IssuerConfig` | The JSON configuration. Unknown keys are rejected. |
| `load_config(path)` | Reads and parses a configuration file. Errors never include the file's contents. |
| `Keys`, `KEY_VARS`, `parse_key` | The seven 32-byte keys, read from named environment variables. |
| `Node::build(config, keys)` | Validates the configuration, opens the vaults, and wires everything together. |
| `Node::gateway`, `Node::shredder`, `Node::writer`, `Node::issuer`, `Node::signer`, `Node::router` | Access to each wired component. |
| `Node::refresh_canaries(now)`, `Node::purge_expired(now)`, `Node::monitor()` | The background operations, callable directly. |
| `Issuer`, `IssuerConfig`, `serve_issuer` | Mints tokens for an upstream host application, under per-caller policy. |
| `AuditStore`, `IssueOutcome` | The keyed audit chain on disk, and the result of one issuance. |

## What a running node does

`tpt-shatter-node config.json` starts four things at once:

1. **The HTTP read and write path**, served by the gateway, over TLS by default.
2. **The token issuer**, on its own listener, if the configuration has an `issuer` section.
3. **The orphan reaper**, which retries failed deletes on `reap_interval_secs`.
4. **The canary monitor**, which refreshes canaries and runs the alarm response on `monitor_interval_secs`. It refreshes once at startup too.
5. **The retention purge**, which erases fragments older than `retention_secs` on `purge_interval_secs`.

The process stops on a fatal error or when it is killed.

## Installation and running

Build the binary from the workspace:

```sh
cargo build -p tpt-shatter-node --release
```

Set the seven keys in the environment (see [Keys](#keys)), then run it with a configuration file:

```sh
tpt-shatter-node /etc/tpt-shatter/node.json
```

The exit status is `0` on success and non-zero on failure. Startup errors name the setting that failed, not its value.

## Configuration

[`examples/in_process_node.rs`](examples/in_process_node.rs) writes a complete configuration as JSON, loads it with `load_config`, and builds a node from it.

| Field | Required | Meaning |
| --- | --- | --- |
| `listen` | yes | Address for the HTTP server, for example `127.0.0.1:8443`. |
| `tls_cert`, `tls_key` | unless `allow_plain_http` | Server certificate chain and private key, PEM. |
| `client_ca` | no | CA that client certificates must chain to. Setting it turns on mutual TLS. |
| `allow_plain_http` | no, default `false` | Serve plain HTTP. Development only. |
| `schema` | yes | Path to the schema JSON. |
| `state_dir` | yes | Directory for the orphan log, the alert log, and the canary epoch marker. |
| `vault_dirs` | yes | Directories `a`, `b`, and `c`, one per vault. |
| `canary_count` | yes | Canaries per epoch. Must be positive. |
| `canary_period_secs` | yes | Epoch length. Must be positive. A week is typical. |
| `alarm_cooldown_secs` | yes | Seconds before the alarm gate can re-arm after a response. |
| `reap_interval_secs` | yes | Seconds between reap passes. Must be positive. |
| `reap_max_attempts` | yes | Attempts an orphan gets before it is abandoned. Must be positive. |
| `monitor_interval_secs` | yes | Seconds between canary and alarm passes. Must be positive. |
| `retention_secs` | yes | Maximum fragment age. Must be at least `canary_period_secs`, so a canary is refreshed before its own retention runs out. |
| `purge_interval_secs` | yes | Seconds between retention passes. Keep it coarser than the monitor interval, because a pass reads and authenticates every fragment. |
| `issuer` | no | The token issuer. Absent means no issuer runs on this node. |

Unknown top-level fields are rejected, so a misspelled setting fails at startup rather than being ignored. Invalid settings are refused before any directory is opened.

## Keys

The node reads seven keys from the environment. Each is 64 hex characters, which is 32 bytes.

| Variable | Used for |
| --- | --- |
| `TPT_KEY_VAULT_A` | Encryption key for vault A's files. |
| `TPT_KEY_VAULT_B` | Encryption key for vault B's files. |
| `TPT_KEY_VAULT_C` | Encryption key for vault C's files. |
| `TPT_KEY_DERIVATION` | Derives fragment IDs. |
| `TPT_KEY_TOKEN` | Signs capability tokens. Rotated by the alarm response. |
| `TPT_KEY_CANARY_MASTER` | Derives each epoch's canary key. |
| `TPT_KEY_AUDIT` | Keys the audit chain. |
| `TPT_KEY_ANALYTICS` | Salts pseudonyms in the analytics feed. Required even when analytics is off. |

Keys are held in memory for the life of the process. Nothing in this crate writes a key to disk. The node refuses to start if any key is missing or not 64 hex characters, and the error names the variable, never its value.

Environment variables are visible to other processes run by the same user on many systems. Deliver keys from a secret store that injects them at start, and do not place them in shell history or in the configuration file.

## Token issuer

The issuer is the only place a capability token is minted. The host application authenticates its own users, then calls the issuer with a caller secret and the shard and scopes it needs.

`POST /v1/tokens` with `Authorization: Bearer <caller secret>` and a JSON body:

```json
{ "shard": "<64 hex characters>", "scopes": ["read"], "ttl_secs": 30 }
```

| Status | Code | When |
| --- | --- | --- |
| 201 | `issued` | Token issued. The body holds `token` and `expires_at`. |
| 400 | `bad_request` | Malformed body, an unknown field, a `delete` scope, an unknown scope, or a TTL above the caller's maximum. |
| 401 | `unauthorized` | Unknown caller secret. |
| 403 | `forbidden` | A valid scope the caller does not hold. |
| 500 | `internal` | The audit record could not be written, so the token was withheld. |

Each caller has:

- a name, and the SHA-256 of its secret (the node never holds the secret itself);
- a list of allowed scopes;
- a maximum TTL.

The issuer compares every configured caller on every request, so timing does not reveal which caller matched. `delete` is never issuable. Erasure is a maintenance operation, not a token.

Every issuance is appended to the audit chain **before** the token is returned. If the append fails, the token is withheld.

## Audit

One keyed, hash-chained audit file in `state_dir` records:

- token issuances, with digests of the token and shard;
- gateway reads and writes, with digests of the token and shard;
- canary alarms, with the vault and index only.

Each entry's MAC covers the previous one, so a deleted or edited entry breaks verification. The chain survives restarts, and it is written before the action it records. An access the chain cannot record is refused.

The audit entries carry digests, not names. The caller's name appears in the access log, not in the chain.

## Installation

```toml
[dependencies]
tpt-shatter-node = { path = "../tpt-shatter-node" }
```

Most users run the binary. The library is for in-process use, such as tests or a tool that needs the same wiring.

## Quick start

```rust
use tpt_shatter_node::{Keys, Node, load_config};

let config = load_config(std::path::Path::new("node.json"))?;
let keys = Keys::from_lookup(|name| std::env::var(name).ok())?;
let node = Node::build(config, keys)?;

node.shredder().shred(&shard, record)?;
let token = node.signer().read().unwrap().issue(&shard, scopes, now)?;
let response = node.gateway().read(token.as_str(), &shard_hex, now_ms);
```

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`in_process_node`](examples/in_process_node.rs) | Loading a configuration from JSON, reading keys by name, building a node, writing a record, reading it back through the gateway, and refreshing canaries. | `cargo run -p tpt-shatter-node --example in_process_node` |
| [`issue_token_request`](examples/issue_token_request.rs) | Running the token issuer: a valid request, the policy refusals, and the audit chain. | `cargo run -p tpt-shatter-node --example issue_token_request` |

## Security properties

- **Fail closed on configuration.** Invalid settings are refused before anything opens. Missing keys stop startup.
- **No secrets in logs.** Logs and alerts never contain tokens, field values, shard keys, or keys. The test suite checks this.
- **Caller secrets stored as digests.** The issuer holds only the SHA-256 of each caller's secret.
- **Audit before action.** Issuances, reads, and writes are recorded before they take effect, and an access that cannot be recorded is refused.
- **Canary response is automatic.** An alarm rotates the token key, so outstanding tokens stop verifying, and notifies security.
- **Retention cannot outlive canaries.** Startup refuses a retention period shorter than the canary period.

## Limitations

- **Single process, no high availability.** A node is one process with local vault directories. There is no replication or failover.
- **Keys come from the environment.** This is adequate only when the environment is injected from a secret store. Key rotation other than the alarm response is manual.
- **The host application is out of scope.** The node trusts the caller secret to identify the host application. Authenticating end users is the host's job.
- **The audit chain records digests, not callers.** To link an issuance to a caller, use the access log.
- **Backups are outside the node.** Backups of the vault directories, the audit file, and the orphan log are the operator's responsibility, and they must follow the same retention rules.
- **Plain HTTP is available for development.** Production should set `tls_cert` and `tls_key`, and should set `client_ca` where clients are known.

## Testing

```sh
cargo test -p tpt-shatter-node
```

Tests cover reading keys by name and rejecting bad hex, a record shredded by the node and read back through the gateway, writes and scope enforcement through the node, a canary read rotating the token key, the absence of secrets from logs and alerts, retention purges keeping live fragments, refusal of retention shorter than the canary period, and refusal of invalid settings. The issuer tests cover valid issuance, uniform refusal of wrong secrets, scope and TTL limits, `delete` never being issuable, malformed requests writing no audit record, and every issuance surviving a restart in the audit chain.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
