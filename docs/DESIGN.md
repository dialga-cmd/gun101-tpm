# System Design

## Actors

- **User** invokes the CLI or Python API and supplies plaintext, a password,
  and an encrypted container path.
- **Application** validates inputs, derives a key with Argon2id, encrypts file
  data with AES-256-GCM, and serializes the container.
- **Platform backend** communicates with the host TPM or platform keystore to
  seal and unseal the data-encryption key.
- **Filesystem** stores plaintext input, encrypted containers, and recovered
  output. It never receives the raw DEK or KEK as a standalone file.
- **CI and release services** build, test, analyze, and publish the package.

## Core actions

1. `encrypt_file()` generates a random DEK and salt.
2. `derive_key()` derives a password-based KEK using Argon2id.
3. The active backend seals the DEK using the TPM and KEK-derived auth value.
4. AES-256-GCM encrypts the file data with a fresh nonce.
5. The container stores protocol metadata, salt, sealed blob, nonce, tag, and
   ciphertext, but no device identifier or plaintext key.
6. `decrypt_file()` parses and validates the container, derives the KEK, asks
   the active backend to unseal the DEK, and authenticates/decrypts the data.

## Trust boundaries

- The password crosses from the user interface into process memory and is
  never intentionally written to the container.
- The DEK and KEK remain in process memory and are cleared after use where the
  Python runtime permits.
- The TPM is trusted to enforce fixed-TPM/fixed-parent sealing and auth checks.
- The filesystem and any other machine are not trusted to provide a valid TPM
  unseal operation.

Platform limitations and threat assumptions are documented in the
[security model](SECURITY.md) and [threat model](THREAT_MODEL.md).