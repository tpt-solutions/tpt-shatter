# Changelog

All notable changes to `tpt-shatter-canary` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CanaryPlan` and `CanaryRotation`: epoch-based, secret-derived canary records, with a configurable count and period.
- `refresh_canaries`: plants the current epoch's canaries and removes the previous epoch's, and does nothing when no refresh is due.
- `CanaryWatch`: an `AccessObserver` that queues an alarm for each observed read or delete of a canary, with `replace` for rotation.
- `Detector`: matches queried fragment IDs against the current canaries.
- `AlarmGate` with `Quiet`, `Fired`, and `Suppressed` outcomes, a cooldown, and a re-arm check. A failed response keeps the gate armed for retry.
- `CanaryMonitor`: drains the watch, runs the gate, and writes alarms to the alert log.
- `Responder` trait for the two response steps: signing-key rotation and security notification.
- `values::canary_value`: field-shaped canary values, including Luhn-valid card numbers and `.invalid` email domains.

### Changed
- `Alarm` and `Responder` are re-exported from `tpt-shatter-common`, where they now live. Existing paths still compile.
