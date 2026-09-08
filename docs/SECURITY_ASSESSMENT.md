# Security Assessment

Assessment date: 2026-09-08

## Scope and assets

The assessment covers the Python package, CLI, encrypted container format,
TPM backends, build pipeline, and release process. The primary assets are
plaintext file contents, the per-file DEK, the password-derived KEK, TPM-sealed
objects, release artifacts, and CI credentials.

## Highest-impact threats

- Password theft or offline password guessing.
- Decryption on a different machine or with a different TPM.
- Ciphertext, authentication-tag, or sealed-blob tampering.
- Weak or incorrect cryptographic implementation.
- Accidental exposure of keys or credentials in containers, logs, or Git.
- Compromise of release automation or distribution artifacts.

## Mitigations

- Argon2id derives a 32-byte KEK using fixed cost parameters and a per-file
  salt.
- AES-256-GCM authenticates every encrypted file with a fresh nonce.
- The container format supports an allowlisted alternative, ChaCha20-Poly1305,
  while retaining AES-256-GCM as the default for compatibility.
- TPM objects use fixed-TPM and fixed-parent attributes and require the
  password-derived auth value.
- Cryptographic primitives come from `cryptography`, `argon2-cffi`, and
  `tpm2-pytss`; no primitives are implemented from scratch.
- Ruff, Bandit, pytest, and reproducible wheel/sdist builds run in GitHub
  Actions on every push and pull request.
- Security reports use private disclosure, and public advisories are created
  after coordinated remediation.

## Residual risks

TPM failure can cause permanent data loss, password compromise affects files
encrypted with that password, Windows sealing is currently emulated, and the
project does not provide forward secrecy or post-quantum protection. These
limitations are documented in the security and threat models.