# tpt-shatter-vault-service

Serves one vault over mTLS, so each vault can run as its own process on its own host.

- `tpt-shatter-vault` (binary): reads a JSON config, opens one `FileVault` with its own
  sealing key, runs retention purges, and serves the vault. Client certificates are required
  and must chain to `client_ca`.
- `RemoteVault` (library): a `VaultBackend` that talks to a served vault. The node uses it
  in place of a local `FileVault`.

The protocol is HTTP/1.1 over TLS 1.3, one request per connection:

| Request | Response |
|---|---|
| `PUT /v1/fragments/{id}` (body = sealed fragment) | `204` |
| `GET /v1/fragments/{id}` | `200` with the body, or `404` |
| `DELETE /v1/fragments/{id}` | `200` with `{"removed": bool}` |

Errors are fixed codes with no body. The service never sees a record, only sealed fragments.
