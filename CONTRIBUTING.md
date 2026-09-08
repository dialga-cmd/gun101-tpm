# Contributing to GUN-101-TPM

First off — thank you for considering contributing to GUN-101-TPM. This
project is a small, security-focused library written and maintained by one
person, and every well-tested pull request makes it meaningfully stronger.

GUN-101-TPM binds encrypted files to the TPM 2.0 hardware on the machine
that created them. Even with the correct password, decryption fails on any
other machine, because the Data Encryption Key (DEK) is sealed inside the
TPM. Getting security libraries like this right requires patience, clear
reasoning, and honest documentation of limitations. All of those are valued
here.

This guide explains what we need help with, how to set up your environment,
the standards we hold code to, and how to get your changes merged.

All contributors must be legally authorized to submit their changes. Each
commit in a pull request must include a `Signed-off-by` trailer (use
`git commit -s`), certifying the Developer Certificate of Origin statement
below. The DCO check must pass before a pull request can be merged.

By adding the trailer, the contributor certifies that they have the right to
submit the work under the project's license and agree to the Developer
Certificate of Origin at https://developercertificate.org/.

---

## Table of Contents

- [What kinds of contributions we need](#what-kinds-of-contributions-we-need)
- [Before you start: caveats](#before-you-start-caveats)
- [Prerequisites and setup](#prerequisites-and-setup)
- [Running the test suite](#running-the-test-suite)
- [Coding standards](#coding-standards)
- [Security-specific contribution rules](#security-specific-contribution-rules)
- [Writing new tests](#writing-new-tests)
- [Development environment notes](#development-environment-notes)
- [Submitting a pull request](#submitting-a-pull-request)
- [Reporting security vulnerabilities](#reporting-security-vulnerabilities)
- [Good first issues](#good-first-issues)

---

## What kinds of contributions we need

- **Bug fixes** — anything that produces wrong output, crashes, or a wrong
  error message.
- **New features** — especially new hardware backends and CLI improvements
  (see [Good first issues](#good-first-issues)).
- **Security improvements** — hardening, parameter reviews, threat-model
  validation, new negative tests, reducing attack surface.
- **Documentation** — fixing inaccuracies, adding examples, improving
  explanations of the security model. Documentation that reflects the
  actual code is as important as the code itself.
- **Tests** — we especially need negative tests (proving something fails the
  way it should) and tests that run without physical TPM hardware.
- **Platform support** — new platforms are the highest-effort, highest-value
  work see [Good first issues](#good-first-issues).

## Before you start: caveats

1. **Read the security model first.** Please read `docs/SECURITY.md` and
   `docs/THREAT_MODEL.md` before touching encryption, key derivation, or the
   backends. A surprising number of "improvements" accidentally weaken one
   of the properties documented there.
2. **Hardware-bound means hardware-bound.** Files encrypted on one machine
   cannot be decrypted on another — by design. A feature that makes files
   portable across machines or decryptable without the TPM is a different
   product, not a contribution.
3. **The Windows backend limitation.** The Linux backend performs genuine
   TPM 2.0 sealing. The Windows TBS backend in
   `src/gun101tpm/backends/windows.py` currently *emulates* sealing with a
   software-only blob (`GUN101_WIN_TBS_V1` header + SHA-256 auth hash) and
   does **not** provide real hardware binding on Windows. This is a known
   gap, tracked openly — it is a great place to contribute, not a secret.
4. **The macOS backend is a stub.** `backends/macos.py` raises
   `NotImplementedError` for every method. An implementation is welcome and
   will likely use the Secure Enclave rather than a TPM.

## Prerequisites and setup

- **Python 3.9+** (`requires-python = ">=3.9"` in `pyproject.toml`).
- **Git** and a **GitHub account.**
- For the Linux backend: a **TPM 2.0 device** (`/dev/tpm0` or `/dev/tpmrm0`),
  the `tss` group membership, and `tpm2-pytss`. If you don't have a physical
  TPM, you can use the `swtpm` software simulator — see
  [docs/TPM_SETUP.md](docs/TPM_SETUP.md). The mocked platform-gate tests do
  not need any hardware.

### Fork and clone

1. Fork the repository on GitHub
   ([github.com/dialga-cmd/gun101-tpm](https://github.com/dialga-cmd/gun101-tpm)).
2. Clone your fork and add the upstream remote:

   ```bash
   git clone https://github.com/<your-username>/gun101-tpm.git
   cd gun101-tpm
   git remote add upstream https://github.com/dialga-cmd/gun101-tpm.git
   ```

3. Create a **new branch** for your work (see
   [branch naming](#branch-naming-and-commit-style) below).

### Install for development

```bash
# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate

# Install the package in editable mode, including the TPM extra
pip install -e .[tpm]

# Install test and static-analysis tools
pip install -e .[dev]
```

The `dev` extra installs pytest, Ruff, and Bandit, which are also run by the
repository's GitHub Actions quality workflow.

## Running the test suite

The full suite:

```bash
pytest tests/ -v --cov=src/gun101tpm --cov-report=term-missing --cov-fail-under=80
```

Coverage excludes the experimental Flet GUI and native Windows TBS calls,
which require platform-specific runtime environments. The Linux backend and
all portable library, handler, KDF, cipher, and CLI paths remain measured.

The tests fall into three groups with different requirements:

| Test file | Needs | Runs on |
|-----------|-------|---------|
| `tests/test_platform_gate.py` | nothing (mocked) | any OS, no hardware |
| `tests/test_tpm.py` | a real TPM 2.0 device or `swtpm` | Linux |
| `tests/test_windows_backend.py` | a TPM via `tbs.dll` | Windows only; skipped elsewhere |

**What passing looks like:**

- On a machine with a reachable TPM 2.0 device (physical or `swtpm`):
  `tests/test_platform_gate.py` passes, `tests/test_tpm.py` passes, and
  `tests/test_windows_backend.py` reports `skipped` (on Linux).
- On Windows with TBS working: the Windows backend tests run and pass.
- The hardware tests are deliberately **not** mocked. If your machine has
  no TPM, `tests/test_tpm.py` will fail with a hardware-availability error —
  that is expected behaviour, not a regression. In that case run the mocked
  subset locally:

  ```bash
  pytest tests/test_platform_gate.py -v
  ```

If you are changing backend or hardware-facing code, please verify against a
real device (`swtpm` is fine) or say explicitly in the PR description which
hardware-dependent tests you could not run.

## Coding standards

- **Type hints are required** on every function and method signature,
  including `-> None`. Code must remain compatible with Python 3.9.
- **Docstrings are required** for all public functions and classes: a
  one-line summary, `Args:` and `Returns:` sections as applicable. The
  existing code in `src/gun101tpm/kdf.py`, `cipher.py`, and `handler.py` is
  the reference style.
- Follow the existing layout: configuration constants live in `config.py`,
  primitives in `kdf.py` / `cipher.py`, backend hardware access behind the
  backend interface under `src/gun101tpm/backends/`.
- Keep the code compatible with the dependency floor in `pyproject.toml`
  (`argon2-cffi>=23.1.0`, `cryptography>=42.0.2`).
- **Never** reduce the Argon2id parameters (`ARGON2_TIME_COST`, 
  `ARGON2_MEMORY_COST`, `ARGON2_PARALLELISM` in `src/gun101tpm/config.py`)
  or shorten the AES-256 key / nonce lengths — under **any** circumstances.
  These are hard security invariants of this project.
- Do not introduce platform-specific code into `handler.py` or `cli.py`;
  hardware differences belong inside a backend.

## Security-specific contribution rules

Any change that touches **key derivation, encryption, decryption, the sealed
container format, or a hardware backend** requires a **written justification
in the PR description** explaining the cryptographic reasoning: what the
change does, what property it preserves or strengthens, and why it cannot be
exploited to bypass the hardware binding.

Additional rules:

- **No new cryptographic primitives from scratch.** Use only well-audited
  libraries: `cryptography`, `argon2-cffi`, and — for hardware access —
  `tpm2-pytss` on Linux. Reimplementing AES, Argon2, or a KDF is an
  automatic rejection.
- **No plaintext keys on disk, ever.** The DEK and KEK must remain in
  memory only, be cleared after use (see `_clear_memory()` in
  `handler.py`), and never be written to a file or logged.
- **Constant-time comparisons** for secrets — `hmac.compare_digest()`
  (see `verify_key()` in `kdf.py`).
- **The container must not carry device identifiers.** Removing the TPM
  fingerprint from containers was an explicit security decision, not an
  accident. Do not re-add one.
- **No `SIGN_ENCRYPT` restricted keys.** The TPM primary object attributes
  are `RESTRICTED | DECRYPT | FIXEDTPM | FIXEDPARENT | SENSITIVEDATAORIGIN`
  — the TPM spec forbids a restricted key that is simultaneously sign and
  decrypt. Preserve that.
- When in doubt about whether a change is security-relevant, treat it as
  security-relevant. The maintainer will do the same.

## Writing new tests

- **Every major new feature must include automated tests** covering its
  normal behaviour and relevant failure cases. A pull request that changes
  externally visible behaviour should add or update tests in `tests/` and
  explain any hardware-dependent coverage that could not be run locally.
- **Every new security-affecting function must have both a positive test**
  (it works correctly, e.g. a round-trip) **and a negative test** (it fails
  safely, e.g. wrong password, tampered ciphertext, corrupted sealed blob).
  Look at `tests/test_tpm.py::test_real_decrypt_wrong_password_fails` and
  `::test_real_decrypt_corrupted_blob_fails` for the established pattern.
- Hardware-facing tests that cannot run on every machine should either
  `pytest.skip` cleanly (like `tests/test_windows_backend.py`) or be kept
  separate, like the un-mocked `tests/test_tpm.py`.
- Prefer `unittest.mock.patch('sys.platform', ...)` over live platform
  assumptions — `tests/test_platform_gate.py` is the reference.
- When you add a test, run it locally before opening the PR and report the
  result in the PR description.

## Development environment notes

- `src/gun101tpm/main.py` is an experimental Flet GUI that mirrors the CLI
  and is tracked in the source tree. Changes to it are welcome but secondary
  to the library and CLI.
- `src/gun101tpm/tpm.py` is a backward-compatibility shim that re-exports
  the backend functions. Keep it working; don't delete it.
- Never commit environment artifacts: `venv/`, `.idea/`, `.mypy_cache/`,
  `.pytest_cache/`, and `__pycache__/` are gitignored. Keep them that way.
- Never commit credentials, private keys, certificates, environment files, or
  generated release artifacts. Use GitHub Actions secrets or environment
  protection instead of putting credentials in source files.

## Submitting a pull request

## Code review standards

Every code change must be proposed through a pull request. A reviewer other
than the author must determine that the change is worthwhile, correctly scoped,
compatible with the supported Python versions, covered by appropriate tests,
and free of known issues that should block release.

Reviewers must check, as applicable:

- correctness, error handling, input validation, and public API compatibility;
- tests for new behavior and regression tests for fixed defects;
- type hints, docstrings, Ruff results, and Bandit results;
- dependency, license, and supply-chain changes;
- cryptographic invariants, threat-model impact, and key-handling behavior;
- documentation, changelog, migration, and release-note updates; and
- CI status, DCO status, and required approvals.

Security-sensitive changes require a written cryptographic justification and a
reviewer who is not the author. Release changes require review before the
release is published. Maintainers must not approve their own pull request.

### Branch naming

Name your branch after the kind of change and its topic:

```text
fix/<short-description>        e.g. fix/decrypt-error-message
feat/<short-description>       e.g. feat/macos-backend
security/<short-description>   e.g. security/constant-time-compare
test/<short-description>       e.g. test/swtpm-detection
docs/<short-description>       e.g. docs/fix-setup-guide
perf/<short-description>       e.g. perf/benchmark-argon2
```

### Commit messages

- One logical change per commit.
- Imperative, present tense summary, ≤ ~72 characters.
- Optional scope hint helps, matching the existing repo style (e.g.
  `code cleanup`, `implement Windows TBS backend with TPM 2.0 support`,
  `Security: hash TPM fingerprint in file metadata`).

```text
feat: add swtpm-based TPM availability detection tests

Demonstrate that check_tpm_available() and get_tpm_fingerprint()
work against a software TPM, so contributors without physical
hardware can validate backend changes.
```

### What to include in the PR description

Use the pull request template. At minimum:

- What the change does and why.
- Any security justification required under the rules above (state
  explicitly if the change does **not** touch key derivation, encryption, or
  decryption, and say so).
- The results of `pytest tests/ -v` (or clearly state which hardware tests
  you could not run and why — for example "macOS backend touched; could only
  run mocked tests on Linux").
- Screenshots for UI/CLI-output changes.

### Review process

1. The maintainer (Aditya Raj) acknowledges the PR, usually within a couple
   of days, often faster.
2. Security-sensitive changes get a careful review focused on the
   cryptographic reasoning; expect questions rather than assumptions.
3. Backend changes should be reviewed by someone who can test the target
   platform if possible.
4. After approval the maintainer merges. You do not need merge rights.

A few reviews — help wanted. If you would like to help review
security-sensitive pull requests, say so in an issue tagged `help wanted`
and an introduction to the project.

## Reporting security vulnerabilities

**Do not open a public GitHub issue for a security vulnerability.**

Private disclosure gives us time to prepare a fix before the vulnerability
is public knowledge, which protects everyone using the library.

- Email the maintainer directly: **adityaraj1234@duck.com**
- You will receive an acknowledgement **within 48 hours**.
- In the email, include: the affected component, a description of the
  vulnerability, steps to reproduce, potential impact, and (if you have one)
  a suggested fix.
- Encrypted reports are appreciated; if you have a public key, please
  include it and we will respond with one.

Track your issue in public — after it is fixed. If you disclosed privately,
you are welcome to write up the fixed issue (without full PoC detail) once
a release containing the fix is out.

Full policy: see [SECURITY_POLICY.md](SECURITY_POLICY.md).

## Good first issues

These are concrete, self-contained tasks matched to this codebase. Pick one,
ask questions in the issue thread, and open a PR when you're ready.

1. **Implement the macOS Secure Enclave backend.**
   `src/gun101tpm/backends/macos.py` is a stub — all four methods raise
   `NotImplementedError`. A real implementation would bind the DEK to the
   Secure Enclave (e.g. via a keychain-backed key) and needs positive and
   negative tests. Most Mac hardware has no TPM 2.0 chip, so this is a
   *different* hardware binding than the Linux backend, deliberately.

2. **Implement real TPM 2.0 seal/unseal for the Windows backend.**
   `src/gun101tpm/backends/windows.py` talks to `tbs.dll` (and does a real
   TPM fingerprint via a raw `TPM2_CreatePrimary` command), but its
   `seal()`/`unseal()` use a software-only emulated blob
   (`GUN101_WIN_TBS_V1` header + SHA-256 auth hash). Replacing that with a
   genuine TPM 2.0 seal/unseal over TBS would close the biggest gap in the
   project.

3. **Add a PCR binding mode.**
   Bind the sealed DEK to chosen PCR values, so decryption additionally
   requires the machine to be in a specific measured boot state (not just
   the same TPM). This needs design discussion first — open an issue.

4. **Turn `gun101tpm check-tpm` into a status page.**
   It currently prints the fingerprint or exits 1. A richer output (backend
   in use, platform, TPM availability, fingerprint, and whether hardware
   binding is genuine vs. emulated) would surface the Windows caveat and the
   macOS stub status. The GUI in `main.py` already has a
   `KEYSTORE: SECURE/OFFLINE/FAULT` indicator to match.

5. **Add `swtpm`-based availability detection tests.**
   Today the coverage is either fully mocked (`tests/test_platform_gate.py`)
   or requires physical hardware (`tests/test_tpm.py`). Tests that boot a
   `swtpm` instance and assert `check_tpm_available()` and
   `get_tpm_fingerprint()` would let contributors without a physical TPM
   validate backend changes in CI.

6. **Add CLI error-path tests.**
  Extend `tests/test_unit.py` with portable tests for unreadable input files,
  encryption/decryption failures, invalid output paths, and TPM diagnostic
  errors. Keep the tests hardware-independent by mocking backend calls.

Something else on your mind that isn't listed? Open an issue describing the
change and the reasoning behind it before writing the code — a quick
discussion can save you the pain of a rejected PR.