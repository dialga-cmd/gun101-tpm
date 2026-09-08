# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) (semver.org).

## [Unreleased]

Work in progress. These changes are present in the working tree / `main`
branch but have not yet been released.

### Added

- `mode` field in the encrypted container (`"TPM"` or `"Unknown"`) recording
  which hardware binding method was used.
- Experimental Flet GUI (`src/gun101tpm/main.py`) with a hardware-vault theme
  and a `KEYSTORE: SECURE / OFFLINE / FAULT` status LED driven by
  `check_tpm_available()`.

### Changed

- `handler.encrypt_file()` and `handler.decrypt_file()` now route through the
  `get_backend()` backend registry and delegate sealing/unsealing to the
  active platform backend instead of hard-coding TPM calls.
- `handler.decrypt_file()` dispatches on the container `mode` field.

### Security

- Container encryption no longer assumes a single backend: hardware-dependent
  behaviour is isolated behind the backend interface in
  `src/gun101tpm/backends/`.

## [1.0.0] - 2026-08-20

Initial release.

### Added

- **Linux TPM 2.0 backend** (`src/gun101tpm/backends/linux.py`) via
  `tpm2-pytss` ESAPI. The DEK is sealed as a KEYEDHASH object under a
  deterministically recreated SYMCIPHER primary key bound to the TPM with
  `FIXEDTPM | FIXEDPARENT | RESTRICTED | DECRYPT | SENSITIVEDATAORIGIN`.
  The password-derived KEK is presented as the TPM object auth value
  (`TPM2B_AUTH`), so both the machine's TPM **and** the password are required
  to unseal.
- **Windows TBS backend** (`src/gun101tpm/backends/windows.py`): `tbs.dll`
  bindings (V2 with V1 fallback) for x64 and ARM64 Windows. `check_available()`
  probes the TBS context and `get_fingerprint()` issues a raw
  `TPM2_CreatePrimary` command for the RSA endorsement key.
  > Known limitation: `seal()`/`unseal()` on Windows currently use a
  > software-only emulated blob (`GUN101_WIN_TBS_V1` header + SHA-256 auth
  > hash) and do not provide genuine TPM hardware binding.
- **Cross-platform backend architecture** (`src/gun101tpm/backends/`): abstract
  `HardwareBackend` interface, platform-based registry with a cached singleton
  (`get_backend()`), `reset_backend()` for tests, and a backward-compatibility
  shim in `src/gun101tpm/tpm.py`.
- **macOS Secure Enclave stub** (`src/gun101tpm/backends/macos.py`) raising
  `NotImplementedError`; implementation not started.
- **AES-256-GCM file encryption** (`src/gun101tpm/cipher.py`) with a random
  12-byte nonce and 16-byte authentication tag per file.
- **Argon2id key derivation** (`src/gun101tpm/kdf.py`) with fixed OWASP-aligned
  parameters: `time_cost=3`, `memory_cost=65536` KiB (64 MiB), `parallelism=4`,
  `hash_len=32`, 16-byte random per-container salt.
- **Command-line interface** (`src/gun101tpm/cli.py`, entry point `gun101tpm`):
  - `gun101tpm check-tpm` — report TPM availability and EK fingerprint.
  - `gun101tpm encrypt FILE [-o OUTPUT]` — default output `FILE.gun101`.
  - `gun101tpm decrypt FILE [-o OUTPUT]` — strips `.gun101` or appends
    `.decrypted`.
  - Interactive password prompt via `getpass` (with `GUN101TPM_PASSWORD`
    environment-variable fallback).
- **Container format v2.0** (`PROTOCOL=GUN-101-TPM`, `VERSION=2.0`): compact
  JSON holding `salt`, `sealed_blob`, `file_nonce`, `file_tag`, and
  `ciphertext` — with no device identifier or KEK-encrypted DEK fields.
- **Live TPM tests** (`tests/test_tpm.py`): hardware availability, EK
  fingerprint format, encrypt/decrypt round-trip, wrong-password rejection,
  and tampered-blob rejection against a real TPM 2.0 device.
- **Mocked platform-gate tests** (`tests/test_platform_gate.py`): backend
  selection per platform, Linux-only gating, macOS stub behaviour, and TPM
  shim delegation.
- **Documentation**: `docs/SECURITY.md` (security model), `docs/THREAT_MODEL.md`
  (threat table), `docs/TPM_SETUP.md` (hardware setup + `swtpm`), and
  `ROADMAP.md`.

### Changed

- Argon2id and AES parameters are compiled into `src/gun101tpm/config.py` and
  cannot be overridden per operation.

### Fixed

- Decryption now rejects containers with an unknown or corrupted protocol /
  version with a clear `ValueError` instead of a cryptic decode failure.
- Key comparison uses `hmac.compare_digest()` for constant-time behaviour; the
  deprecated `_constant_time_compare` helper was removed from `kdf.py`.
- A defensive length guard keeps the derived-key path from silently returning a
  non-32-byte value even though Argon2id with `hash_len=32` should never
  produce one.
- The sealed-DEK path no longer exposes `dek_nonce` / `dek_ciphertext` /
  `dek_tag` fields in the container — the DEK is obtainable **only** through a
  successful hardware unseal.

### Security

- Encrypted containers contain **no TPM fingerprint or other device
  identifier**; the TPM-bound sealed object is the binding check.
- Wrong-machine decryption fails with a clear error rather than a confusing
  hardware failure.
- Limited-I/O and long-term-use caveats (single-machine only, permanent loss
  on TPM failure, no forward secrecy, ~128-bit post-quantum margin for
  AES-256) are documented in `docs/SECURITY.md`.

---

This project follows Semantic Versioning (semver.org). Added / Changed / Fixed
/ Security entries are written from the actual codebase; see `pyproject.toml`
for the current version and `git log` for per-change history.