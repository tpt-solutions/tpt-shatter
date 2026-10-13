# Changelog

All notable changes to `tpt-shatter-anonymize` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `bucket` and `Bucket`: fixed-width integer ranges using Euclidean division, so negative values bucket correctly.
- `pseudonymize`: length-prefixed salted SHA-256, rejecting an empty salt.
- `add_noise` and `laplace_from_uniform`: Laplace noise for epsilon-differential privacy, with parameter validation.
- `check_k_anonymity`: a batch-level gate that refuses cohorts smaller than `k`.
- `mask`: display masking that never reveals more than the requested tail, and masks short values completely.
- Property tests for bucket containment, pseudonym determinism, and masking bounds, and a statistical test for the Laplace scale.
