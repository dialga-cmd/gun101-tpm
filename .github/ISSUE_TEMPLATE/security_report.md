---
name: Security vulnerability report
about: Report a security vulnerability in GUN-101-TPM
title: ''
labels: ''
assignees: ''
---

# Please don't file security vulnerabilities here

**Do not open a public GitHub issue or pull request for a security
vulnerability.**

GUN-101-TPM is an encryption tool: a vulnerability in it puts users' confidential
files at risk. If you describe a live vulnerability in a public issue, it is
visible to everyone including attackers, and users are on the clock between the
disclosure and the release of a fix. Coordinated, private disclosure gives the
maintainer time to fix the issue and release a patched version *before* the
details are public — which protects every user of the library.

## Instead, email the maintainer

Email the full details to **adityaraj1234@duck.com** as a private report.
Avoid including code blocks or reproduction details in this issue template —
the goal is to reach the maintainer directly, not to describe the bug here.

## Response commitment

The maintainer — Aditya Raj — commits to:

- **Acknowledgement within 48 hours** of receiving your email.
- A **fix timeline communicated within 7 days** of acknowledgement.
- Coordinated disclosure: once a fix is released, you are welcome to
  write up the *fixed* issue publicly (without a live exploit) and will be
  credited in the CHANGELOG unless you request anonymity.

## What to include in the private report

When you email, please use this structure:

### Affected component

<!-- e.g. key derivation (kdf.py), AES-GCM (cipher.py), container format
  (handler.py), Linux/Windows/macOS backend, CLI. -->

### Description of the vulnerability

<!-- What is the weakness, and how does it break one of the guarantees in
  docs/SECURITY.md or docs/THREAT_MODEL.md? -->

### Steps to reproduce

<!-- Minimal code/commands; avoid publishing a working exploit in full detail. -->

### Potential impact

<!-- What can an attacker do, and who is affected? -->

### Suggested fix (optional)

<!-- A proposed remediation, if you have one. -->

---

Thank you for keeping GUN-101-TPM and its users safe. Full disclosure
guidelines are in [SECURITY_POLICY.md](../../SECURITY_POLICY.md).