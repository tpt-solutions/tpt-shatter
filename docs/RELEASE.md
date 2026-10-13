# Release Checklist

Use this before tagging a release. Tagging `v1.0.0` is a human decision: the checklist can
be complete while the release is still not ready, because the open gaps in `todo.md` are
about deployment, not code. Every step names the command or file that proves it.

## 1. Code gates (run from a clean checkout of the tag candidate)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check` (advisories, bans, licenses, sources)
- [ ] `cargo audit` is clean. It runs in CI through `rustsec/audit-check`; run it locally
      too if `cargo-audit` is installed.
- [ ] Latency measurement recorded, with the output of
      `cargo test -p tpt-shatter-node read_path_latency -- --ignored --nocapture`. It is not a
      gate; record the numbers in the release notes.

## 2. Documents

- [ ] `CHANGELOG.md` has an entry for this version with every user-visible change.
- [ ] `docs/THIRD_PARTY_NOTICES.md` is regenerated from `cargo metadata` and matches the
      lock file.
- [ ] The license texts and any Apache-2.0 `NOTICE` files of the linked crates are shipped with
      the binary. This is manual; see the notices file.
- [ ] `docs/COMPLIANCE.md` and `docs/RUNBOOK.md` match the code. Gaps marked **GAP** are
      listed in the release notes as known gaps.
- [ ] `docs/SECURITY_REVIEW.md` open items are either fixed or listed in the release notes.
- [ ] `SECURITY.md` disclosure contact is current.

## 3. Versioning

- [ ] `version` in the workspace `Cargo.toml` is the release version.
- [ ] `Cargo.lock` is committed and matches `Cargo.toml`.

## 4. Known gaps that block a production deployment

A release can pass sections 1 to 3 and still be unsafe to deploy. Before deploying, confirm
each of these is either built or accepted in writing:

- Key delivery is from environment variables; there is no secret store (RUNBOOK section 1).
- No backups, restore tooling, or restore drill. Erasure does not reach backups.
- Key destruction is not wired into erasure, so overwrite erasure is not guaranteed on SSDs
  or copy-on-write volumes.
- Canary alarms write to a log file; no pager or webhook delivery.
- The audit event does not record the calling identity.
- No Kubernetes, Terraform, or OPA policy; network isolation is not enforced by this code.

## 5. Tag and publish

- [ ] Commit the release changes on the release branch, and get review.
- [ ] Create an annotated tag, for example `git tag -a v1.0.0 -m "tpt-shatter v1.0.0"`.
- [ ] Push the tag only after the release owner approves. Nothing here publishes to a
      registry: all crates are `publish = false`.
