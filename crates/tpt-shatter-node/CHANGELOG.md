# Changelog

All notable changes to `tpt-shatter-node` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `tpt-shatter-node` binary: runs one node from a JSON configuration file, with the HTTP read and write path, the token issuer, the orphan reaper, the canary monitor, and the retention purge.
- `Config` and `load_config`, with unknown fields rejected and invalid settings refused before anything opens.
- `Keys` and `KEY_VARS`: seven 32-byte keys read by name from `TPT_KEY_*` environment variables, with errors that never include values.
- `Node::build` and accessors for the gateway, shredder, writer, issuer, signer, and router, plus `refresh_canaries`, `purge_expired`, and `monitor`.
- Token issuer (`Issuer`, `serve_issuer`): per-caller secret digests, scope and TTL policy, `delete` never issuable, and issuance recorded in the audit chain before the token is returned.
- `AuditStore`: a keyed, hash-chained audit file covering issuances, reads, writes, and canary alarms.
- Node-level tests that write a record through the node and read it back through the gateway, and that check logs and alerts for secrets.
- `RemoteVaults::server_names` (optional `VaultServerNames`): one certificate name per vault service, for deployments where each vault runs under its own name. A partial map is refused. Without it, `server_name` applies to all three vaults, as before.
- `gateway_alarm` config (`GatewayAlarm`, `AlarmPeerConfig`): the gateways that receive a new signing key when a canary alarm fires, with the node's client identity and a per-push timeout.


### Changed
- `AuditStore` is re-exported from `tpt-shatter-common`, where it now lives. Its behavior is unchanged.
- `Node::responder` pushes the new key to every configured gateway before switching this node. The version comes from the signer, not from an in-process counter, so a restarted node does not reuse a version a gateway already holds.
- `canary_push` (optional config): after each refresh, the monitor pushes the canary list to
  the assembler's list listener. `push_canary_ids` does the push. A failed push is logged and
  retried on the next pass.
