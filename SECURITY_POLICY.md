# Security Policy — GUN-101-TPM

GUN-101-TPM is a hardware-bound file encryption library. Taking a security
issue in it seriously means fixing it privately before it becomes public
knowledge. This page explains which versions we support, how to report a
vulnerability, and what you can expect from us.

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| `1.0.x` | ✅ Yes | Current release line. Receives security fixes. |
| `< 1.0` | ❌ No | Never released to PyPI; development history only. |

Only the current minor release receives security fixes. If you need a fix on
an older supported version, say so in your report and we will consider a
backport. Unsupported versions should be upgraded rather than patched.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**
Use GitHub's private security advisories ("Report a vulnerability" button on
the repo's **Security** tab) **or** email the maintainer directly:

**adityaraj1234@duck.com**

Email is the primary channel. GitHub private advisories are also welcome, but
if you email, your report is never visible to anyone but the maintainer.

### Why not a public issue?

A public disclosure before a fix is ready puts every user of the library at
risk: attackers can read the issue the same moment users can. Private
disclosure gives us time to ship a patched release first.

### What to include in a report

- **Affected component** — e.g. key derivation (`src/gun101tpm/kdf.py`),
  AES-GCM (`src/gun101tpm/cipher.py`), container format / orchestration
  (`src/gun101tpm/handler.py`), a hardware backend
  (`src/gun101tpm/backends/*.py`), or the CLI (`src/gun101tpm/cli.py`).
- **Description of the vulnerability** — what is the weakness, and which
  guarantee from [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) does it break?
- **Steps to reproduce** — minimal code or commands. If you have a working
  exploit, describe the idea rather than publishing a usable exploit in full.
- **Potential impact** — what an attacker could do, and who is affected.
- **Suggested fix (optional)** — a proposed remediation, if you have one.

If the report is incomplete, we will follow up with targeted questions rather
than dismissing it.

## Response Timeline

- **Acknowledgement** — within **48 hours** of receiving the report.
- **Fix timeline** — communicated within **7 days** of acknowledgement. This
  is the timeline for a fix; a patch release may follow.
- **Coordinated disclosure** — we will not make details public until a fix is
  released, and we will not embargo a researcher longer than is necessary to
  ship the fix responsibly. Once the fix is out, the researcher is welcome to
  publish a write-up of the *fixed* issue.

## Credit

Researchers who report vulnerabilities responsibly — and who follow this
policy — will be credited in the CHANGELOG and in the acknowledgements section
of the README unless they explicitly request anonymity. If you prefer not to
be named, just say so in your report; that choice will be respected.

## Scope

The in-scope security guarantees of this library are described in full in
[docs/SECURITY.md](docs/SECURITY.md) (security model) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (threat table with code
references). In brief, the library's guarantees are:

- Files are bound to the originating hardware module: without it, decryption
  fails even with the correct password.
- Both the correct password **and** a successful hardware unseal are required.
- Ciphertext tampering is detected via AES-256-GCM authentication.
- Argon2id parameters and AES key/nonce lengths are fixed and may not be
  weakened.

**In scope:** weaknesses in key derivation, encryption, decryption, the
sealed container format, or any hardware backend that break, weaken, or
bypass the guarantees above, including recovery of a sealed DEK without the
original hardware module.

**Known limitations, not vulnerabilities** (see `docs/SECURITY.md` for the
full list): permanent data loss if the TPM fails or the machine is lost,
single-machine-only design, no cross-device portability, no key rotation,
fixed Argon2id parameters, no forward secrecy after password compromise, and
~128-bit post-quantum margin for AES-256. These are deliberate design
trade-offs.

**Partially supported platforms:** the Windows TBS backend
(`src/gun101tpm/backends/windows.py`) currently *emulates* seal/unseal with a
software-only blob (`GUN101_WIN_TBS_V1` header + SHA-256 auth hash) and does
**not** provide genuine TPM hardware binding; the macOS backend is an
unimplemented stub. Reports about these backends are welcome —
please label the affected component clearly so we can triage appropriately.

**Reporting bugs:** suspected vulnerabilities should go to the channels above.
General bugs go to the GitHub issue tracker's bug report template.

## On Disclosure

If a vulnerability is under active exploitation in the wild, we will prioritise
releasing an emergency fix and coordinate disclosure with the reporter
accordingly. We aim to be transparent about what we have fixed, when, and what
users should do (upgrade) — without releasing live exploit details before the
fix is broadly available.

Public vulnerability records are maintained through GitHub Security Advisories
and the project's changelog. After coordinated disclosure and a fixed release,
the advisory records the affected versions, severity, remediation, and public
references. Unresolved reports remain private until disclosure is safe.

Public advisory archive:
https://github.com/dialga-cmd/gun101-tpm/security/advisories

## Automated Analysis and Testing

Every push and pull request is checked by the GitHub Actions quality workflow.
Ruff performs static source analysis, and Bandit checks the maintained Python
package for common Python security weaknesses. Vendored generated files under
`src/gun101tpm/build/` are excluded from Bandit because they are not project
source and are not executed as part of the package.

The same workflow runs the pytest suite as dynamic analysis. Pytest assertions
remain enabled, and hardware-dependent tests skip cleanly when a TPM is not
available. A release is expected to have passing static analysis and tests
before publication.

Medium- and high-severity findings confirmed by either analysis process are
triaged as security issues. They are fixed or mitigated in a timely patch,
documented in the changelog when user impact exists, and verified by a
regression test where practical.

Dependency SCA findings follow the thresholds in
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md): critical and high findings block
changes immediately, medium findings block the next release, and prohibited
licenses block introduction. Bandit medium and high findings block changes;
lower-severity findings require review and an explicit suppression rationale
before merging.