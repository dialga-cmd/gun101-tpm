# GUN-101-TPM: Hardware-bound File Encryption

GUN-101-TPM creates encrypted files that can only be decrypted on the machine that created them.
Even with the correct password, decryption fails on any other machine because the encryption key
is sealed inside the Trusted Platform Module (TPM 2.0) hardware.

## ⚠️ Important Security Notes

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
5. The TPM's Endorsement Key (EK) public area is hashed to form a fingerprint, stored in the container.
   During decryption, the fingerprint is checked first — if it doesn't match, the operation fails
   immediately without contacting the TPM.

- TPM 2.0 chip
- `tpm2-pytss` Python package (optional install)

## 📦 Installation

```bash
# Install base package (without TPM support)
pip install gun101-tpm

# Install with TPM support
pip install gun101-tpm[tpm]
```

## 💻 Usage

### Check TPM Availability

```bash
gun1
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

## 🆚 When to Use Which GUN-101 Mode

| Mode          | Key Binding              | Portability | Use Case                                  |
|---------------|--------------------------|-------------|-------------------------------------------|
| GUN-101       | Password only            | High        | General purpose, cross-device             |
| GUN-101-GKP   | Password + GPG key       | Medium      | Shared environments with key distribution |
| GUN-101-TPM   | Password + TPM 2.0 seal  | None        | Maximum security on a single trusted device |

## 📚 Documentation

- [Security Model](docs/SECURITY.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [TPM Setup Guide](docs/TPM_SETUP.md)

## 🛡️ License

MIT License - see [LICENSE](LICENSE) file for details.

## 🐛 Reporting Issues

Please report security issues and bugs via the GitHub issue tracker.