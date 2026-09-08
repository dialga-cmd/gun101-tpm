# GUN-101-TPM: Hardware-bound File Encryption

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14547/badge)](https://www.bestpractices.dev/projects/14547)

## Platform Support

**GUN-101-TPM is currently Linux-first.** TPM 2.0 hardware binding is fully supported on Linux. Windows support is **work in progress** — a native TBS-based backend exists but its seal/unseal is still emulated and not yet provably hardware-bound. macOS is not yet supported.

- **Linux**: Fully supported with `/dev/tpm0` or `/dev/tpmrm0`
- **Windows**: **Work in progress** — native TBS-backed backend (`tbs.dll`, x64/ARM64) with `check-tpm` and fingerprint support, but seal/unseal currently uses a software-emulated blob rather than genuine TPM binding
- **macOS**: Not supported — most Mac hardware lacks TPM 2.0 chips; would require a Secure Enclave-based backend (planned for future)

**Installation implications**:
- `pip install gun101-tpm[tpm]` installs cleanly on any OS via the conditional dependency `tpm2-pytss>=2.3.0; sys_platform == 'linux'` in `pyproject.toml`
- On non-Linux OS, the runtime check `_check_platform_supported()` in `tpm.py` raises a clear `RuntimeError` without importing `tpm2_pytss`
- The non-TPM GUN-101 modes (password-only) work cross-platform

---

## What problem does this solve?

Traditional encryption protects data with a password alone. If that password leaks or is
brute-forced, anyone can decrypt the file on any machine. What if the encrypted data should only
be readable on the specific device that produced it?

**GUN-101-TPM** solves this by binding encrypted files to the physical TPM 2.0 chip of the machine
that created them. Even with the correct password, decryption fails on any other machine, because
the encryption key is sealed inside the Trusted Platform Module (TPM 2.0) hardware and cannot be
exported. This makes it ideal for protecting sensitive data on a single trusted device against
password theft, key exfiltration, and offline decryption on attacker-owned hardware.

## Important Security Notes

- **Hardware-bound**: Without the original TPM, decryption is impossible — even with the password.
- **Two-layer protection**: Requires both the password-derived key and the TPM seal.
- **No recovery**: If your machine's TPM fails or you lose the machine, **you cannot recover your files**.
  Do not use this mode for files that require portability or long-term archival without backup.
- **Not quantum-resistant**: AES-256 provides ~128-bit post-quantum security; TPM sealing varies by vendor.
- **TPM 2.0 chip and proper drivers are required.**

1. A random data encryption key (DEK) is generated for each file.
2. The DEK is encrypted with a Key Encryption Key (KEK) derived from your password via Argon2id.
3. The encrypted DEK is sealed to the TPM using a symmetric key bound to the TPM.
4. The file itself is encrypted with the DEK using AES-256-GCM.
5. The DEK is sealed to the TPM. The encrypted container contains no TPM fingerprint or other
  encrypting-device identifier; during decryption, the TPM itself must successfully unseal the DEK.

- TPM 2.0 chip
- `tpm2-pytss` Python package (optional install)

## Installation

```bash
# Install base package (without TPM support)
pip install gun101-tpm

# Install with TPM support
pip install gun101-tpm[tpm]
```

## Usage

### Check TPM Availability

```bash
gun101tpm check-tpm
```

### Encrypt a File

```bash
gun101tpm encrypt secret.pdf
# Enter password when prompted
# Output: secret.pdf.gun101
```

### Decrypt a File

```bash
gun101tpm decrypt secret.pdf.gun101
# Enter password when prompted
# Output: secret.pdf (if on the same machine)
```

## When to Use Which GUN-101 Mode

| Mode          | Key Binding              | Portability | Use Case                                  |
|---------------|--------------------------|-------------|-------------------------------------------|
| GUN-101       | Password only            | High        | General purpose, cross-device             |
| GUN-101-GKP   | Password + GPG key       | Medium      | Shared environments with key distribution |
| GUN-101-TPM   | Password + TPM 2.0 seal  | None        | Maximum security on a single trusted device |

## Documentation

- [Command-line and Python interface](docs/INTERFACE.md)
- [Security Model](docs/SECURITY.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [TPM Setup Guide](docs/TPM_SETUP.md)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Reporting Issues

Please report reproducible bugs and enhancement requests via the [GitHub issue tracker](https://github.com/dialga-cmd/gun101-tpm/issues).
For security vulnerabilities, do not open a public issue; follow the
[private vulnerability reporting process](SECURITY_POLICY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, coding
standards, security-specific contribution requirements, testing expectations,
and pull request guidance.