# tpt-shatter-anonymize

Pure anonymization primitives for tpt-shatter: range bucketing, salted pseudonyms, Laplace noise, a k-anonymity gate, and display masking.

Every function here is a building block. None of them decides policy. The [emitter](../tpt-shatter-emitter/) combines them into a per-field policy, and the [gateway](../tpt-shatter-gateway/) uses masking when it has to show a value.

> **Status:** implemented and tested, including property tests. Not published to crates.io (`publish = false`).

## Contents

- [What it provides](#what-it-provides)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Choosing the right primitive](#choosing-the-right-primitive)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Testing](#testing)
- [Changelog](CHANGELOG.md)
- [License](#license)

## What it provides

| Function | Returns | Use it to |
| --- | --- | --- |
| `bucket(value, width)` | `Bucket` (inclusive `lo()` and `hi()`, displays as `lo-hi`) | Replace an exact number with a range, such as `1994` → `1990-1999`. |
| `pseudonymize(salt, value)` | `[u8; 32]` salted SHA-256 digest | Replace an identifier with a stable, non-reversible token that still joins across records. |
| `add_noise(value, sensitivity, epsilon)` | `f64` value plus Laplace noise | Release a numeric result with epsilon-differential privacy for one query. |
| `laplace_from_uniform(u, scale)` | `f64` | The inverse-CDF transform behind `add_noise`, exposed so it can be tested without randomness. |
| `check_k_anonymity(cohort_sizes, k)` | `Result<(), ShatterError>` | Refuse to release a batch if any group of quasi-identifiers is smaller than `k`. |
| `mask(value, keep_last)` | `String` | Show only the last few characters of a value, for display. |

## Installation

```toml
[dependencies]
tpt-shatter-anonymize = { path = "../tpt-shatter-anonymize" }
```

## Quick start

```rust
use tpt_shatter_anonymize::{bucket, check_k_anonymity, mask, pseudonymize};

let year = bucket(1994, 10)?;          // 1990-1999
let id = pseudonymize(b"secret-salt", b"alice")?; // 32-byte digest
check_k_anonymity(&[12, 7, 5], 5)?;    // every cohort has at least 5
let shown = mask("4000000000000002", 4); // ************0002
```

## Examples

| Example | Shows | Run |
| --- | --- | --- |
| [`anonymize_values`](examples/anonymize_values.rs) | Every primitive on synthetic values, including the refusal paths. | `cargo run -p tpt-shatter-anonymize --example anonymize_values` |

## Choosing the right primitive

- **Exact values are never released.** Bucket a number when a range is enough. Mask a string when a suffix is enough.
- **Pseudonyms are only as strong as the salt.** The salt must be a real secret, kept outside the code. An empty salt is rejected, because a low-entropy input such as a phone number could then be brute-forced.
- **Pseudonyms are deterministic.** The same input and salt always give the same output. That is what makes them joinable, and it is also why the salt must stay secret.
- **k-anonymity is a gate, not a transform.** It decides whether a batch may be released at all. Combine it with bucketing so that cohorts can reach size `k`.

## Security properties

- **No I/O.** Nothing here touches the filesystem or network. The only randomness is the thread-local generator used by `add_noise`.
- **Length-prefixed hashing.** `pseudonymize` prefixes the salt with its length, so the pairs `("ab", "c")` and `("a", "bc")` cannot collide.
- **Fail closed on bad parameters.** A zero width, a zero `k`, a non-positive epsilon, or a non-finite value returns `InvalidParameter` rather than a silent default.
- **Masking never reveals more than asked.** If `keep_last` covers the whole value, the entire value is masked. A short value cannot be shown in full by accident.

## Limitations

- **Differential privacy covers one query.** `add_noise` does not track a privacy budget. Repeated queries on the same data spend privacy with nothing to stop them. Budget accounting belongs to the caller.
- **Floating-point Laplace is not a vetted DP library.** Samples come from `f64` arithmetic, and floating-point Laplace mechanisms are known to be vulnerable to precision attacks. Treat `add_noise` as a building block, and use a vetted library for any release that carries real privacy risk.
- **Bucketing works on `i64` only.** Decimal or currency values need scaling to integers first.
- **k-anonymity does not prevent attribute disclosure.** A cohort of five can still share a sensitive value. Pair the gate with other checks where that matters.

## Testing

```sh
cargo test -p tpt-shatter-anonymize
```

The suite includes property tests (`proptest`) for bucket containment and width, pseudonym determinism, and masking bounds, plus a statistical test that the Laplace sampler's mean and mean absolute value match its scale.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option. See [NOTICE](../../NOTICE).
