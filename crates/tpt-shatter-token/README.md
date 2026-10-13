# tpt-shatter-token

Stateless capability tokens for tpt-shatter. A token says, for a short time, that its holder may perform specific operations (`Read`, `Write`, `Delete`) on one specific shard. Verification needs only the signing key, not a session store.

> **Status:** implemented and tested, including property tests that feed arbitrary input to the verifier. Not published to crates.io (`publish = false`).

## Contents

- [What it provides](#what-it-provides)
- [Token format](#token-format)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Design decisions](#design-decisions)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Item | Purpose |
| --- | --- |
| `Signer::new(key_version, key)` | Holds a 256-bit HMAC key and its version. Key bytes are zeroized on drop. |
| `Signer::issue` / `issue_with_ttl` | Mints a token for a shard and scope set. The TTL defaults to 60 seconds and may be set from 1 to 300. |
| `Signer::verify` | Checks the signature, key version, and expiry, and returns the claims. |
| `Signer::verify_for_shard` | As `verify`, and also checks that the token is bound to the given shard. |
| `Signer::authorize` | As `verify_for_shard`, and also checks that the required `Scope` is granted. This is the call the gateway makes. |
| `Signer::rotate` | Installs a new key and version. Every token signed under the old key stops verifying at once. |
| `TOKEN_VERSION`, `MAX_TTL_SECS`, `CLOCK_SKEW_SECS` | Format version (1), the longest allowed lifetime (300 s), and how far in the future an issue time may be (5 s). |

## Token format

A token is `base64url(payload || tag)`, with no padding:

| Field | Bytes | Contents |
| --- | --- | --- |
| version | 1 | Format version, currently `1`. |
| key version | 4 | Big-endian. Must match the signer's current version. |
| id | 32 | Random, unique per token. |
| scopes | 4 | Bit set of granted scopes. |
| issued at | 8 | Unix seconds. |
| expires at | 8 | Unix seconds. |
| shard key | 32 | The bound shard. |
| tag | 32 | HMAC-SHA256 over everything before it. |

Every token is 121 bytes before encoding, which is 162 characters after it.

## Installation

```toml
[dependencies]
tpt-shatter-token = { path = "../tpt-shatter-token" }
tpt-shatter-common = { path = "../tpt-shatter-common" }
```

## Quick start

```rust
use tpt_shatter_common::{Scope, Scopes, ShardKey};
use tpt_shatter_token::Signer;

let signer = Signer::new(1, [0x11; 32]);   // use a key from a secret store
let shard = ShardKey::from_bytes([0x42; 32]);
let now = 1_700_000_000;

let token = signer.issue(&shard, Scopes::from_scopes(&[Scope::Read]), now)?;

// Later, on the read path:
signer.authorize(token.as_str(), &shard, Scope::Read, now + 1)?;
```

`issue` returns a `Zeroizing<String>`. Treat it as a bearer secret: send it to the caller, and never log it.

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`issue_and_authorize`](examples/issue_and_authorize.rs) | Issuing, shard and scope checks, refusals, expiry, the TTL cap, and rotation. | `cargo run -p tpt-shatter-token --example issue_and_authorize` |

## Design decisions

- **Short lifetimes.** The default is 60 seconds and the cap is 300. Expiry is strict: a token is dead at its expiry second.
- **Replay is accepted within the lifetime.** Tokens are not single-use. A stolen token works until it expires, at most 60 seconds, and only against its bound shard and scopes. A nonce store would make verification stateful, so this design does not use one.
- **Rotation is the emergency lever.** Rotating the key invalidates every outstanding token immediately. The canary response uses this.
- **The shard key travels inside the token.** The gateway routes by it, so whoever holds a token also holds the routing key for its lifetime. Vault access still requires separate assembler credentials.
- **Keys come from the caller.** This crate does not generate or store keys.

## Security properties

- **Authenticated, not just encoded.** The tag covers every field. Flipping any bit fails verification with `InvalidToken`.
- **Constant-time shard comparison.** `verify_for_shard` compares shard keys without early exit.
- **Uniform failures.** A forged token, a wrong key version, and a malformed string all return `InvalidToken`. An expired token returns `TokenExpired`. A wrong shard or missing scope returns `Unauthorized`. The gateway maps all of these to one public `401`.
- **Bounded clock skew.** An issue time more than 5 seconds in the future is rejected, so a token minted by a clock running ahead cannot be used early.
- **Random, unique IDs.** Each token carries 256 bits of randomness from the thread-local CSPRNG.
- **Redacted claims.** `CapabilityToken`'s `Debug` output hides the shard key.
- **Property-tested parser.** Arbitrary strings and arbitrary bytes never verify and never panic.

## Limitations

- **No revocation short of rotation.** A single token cannot be revoked before it expires. Rotate the key to revoke everything, or wait out the lifetime.
- **Holders can read the shard key.** Anyone who holds a token can extract its shard key. This is a known property of the design, and it is why lifetimes are short.
- **No key provisioning.** How keys are delivered, rotated on a schedule, and stored is outside this crate.
- **Time is supplied by the caller.** `now` is an argument, so a caller with a wrong clock gets wrong answers. The node reads the system clock and passes it in.

## Testing

```sh
cargo test -p tpt-shatter-token
```

Tests cover round trips, expiry boundaries, clock-skew tolerance, bit-flip tampering, wrong keys, rotation, shard and scope checks, TTL limits, and arbitrary-input property tests.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
