# Security Assurance Case

## Claim

GUN-101-TPM's documented security requirements are implemented for the
supported Linux TPM 2.0 backend, within the limitations stated in the security
model.

## Threat model and assets

The primary assets are plaintext files, the per-file data-encryption key, the
password-derived key, TPM-sealed objects, encrypted containers, and release
artifacts. The threat model covers password theft, offline guessing, movement
to another machine, container tampering, weak cryptography, key leakage, and
release-pipeline compromise.

https://github.com/dialga-cmd/gun101-tpm/blob/main/docs/THREAT_MODEL.md

## Trust boundaries

- User input enters the CLI or Python API and is validated before processing.
- The application process holds plaintext and transient key material in memory.
- The TPM boundary enforces fixed-TPM/fixed-parent sealing and password-derived
  authorization.
- The filesystem stores containers but is not trusted to perform a valid TPM
  unseal.
- CI and release services are separate trust boundaries with least-privilege
  permissions and keyless Sigstore/PyPI publishing.

https://github.com/dialga-cmd/gun101-tpm/blob/main/docs/DESIGN.md

## Secure-design argument

- AES-256-GCM and Argon2id are called from reviewed FLOSS libraries.
- ChaCha20-Poly1305 is available through the same reviewed cryptography
  library, with an allowlisted algorithm field and AES-256-GCM default.
- Keys, salts, and nonces use cryptographically secure randomness.
- TPM sealing requires both the original hardware and password-derived auth.
- Containers do not include TPM identifiers or plaintext/portable key wraps.
- Fixed key, nonce, and KDF parameters prevent weakening through configuration.
- Input types, protocol/version values, base64 fields, lengths, and authenticated
  ciphertext are validated before use.

## Common-weakness argument

- Tampering is detected by GCM authentication and TPM blob validation.
- Password guessing is slowed by fixed-cost Argon2id with a per-file salt.
- Timing-sensitive key comparison uses `hmac.compare_digest()`.
- Static analysis uses Ruff and Bandit; dependency analysis uses `pip-audit`.
- Automated tests include positive and negative paths and enforce 80% statement
  coverage for portable production code.
- Release publication is gated on the same dynamic test suite with Python
  assertions enabled. Security-critical runtime checks use explicit exceptions
  rather than relying on assertions that optimized Python could remove.
- Release assets have SHA-256 manifests and Sigstore verification instructions.

## Residual risks

TPM loss causes permanent data loss, the Windows backend is not yet genuine
hardware sealing, there is no forward secrecy, and the design is not
post-quantum. These are documented limitations rather than hidden assumptions.

https://github.com/dialga-cmd/gun101-tpm/blob/main/docs/SECURITY.md