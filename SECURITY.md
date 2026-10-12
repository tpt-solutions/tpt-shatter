# Security Policy

tpt-shatter is a security architecture, so we take vulnerability reports seriously.

## Reporting a vulnerability

Do not open a public issue for security problems. Use GitHub's private vulnerability
reporting on this repository (Security tab → "Report a vulnerability").

Please include:

- A description of the issue and its impact
- Steps to reproduce, using synthetic data only
- The affected crate(s) and commit or version

We aim to acknowledge reports within 3 business days.

## Scope

In scope: all crates in this workspace, the infrastructure and policy code, and the CI pipeline.
Out of scope: side-channel attacks requiring hardware access (see DESIGN.md §7.2).

Never include real personal data, real credentials, or live canary values in a report.
