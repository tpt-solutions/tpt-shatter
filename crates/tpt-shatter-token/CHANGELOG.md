# Changelog

All notable changes to `tpt-shatter-token` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Signer` with `issue`, `issue_with_ttl`, `verify`, `verify_for_shard`, `authorize`, and `rotate`.
- Token format version 1: `base64url(payload || HMAC-SHA256 tag)`, 121 bytes before encoding.
- A default lifetime of 60 seconds, a maximum of 300 seconds, and a 5-second allowance for issue-time clock skew.
- Key rotation by version, which invalidates every outstanding token immediately.
- Property tests that feed arbitrary strings and bytes to the verifier.
