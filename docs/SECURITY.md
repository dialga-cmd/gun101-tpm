# Security Model — GUN-101-TPM

## What This Tool Protects Against

- **Unauthorized decryption on other machines**: Files are bound to the original TPM 2.0 device. Even with the correct password, decryption fails on any other machine because the Data Encryption Key (DEK) is sealed to the TPM and cannot be exported. The TPM's `tr_set_auth` gates the unseal operation on the password-derived auth value, so both the TPM and the correct password are required.

- **Pure-password-based decryption**: Decryption requires both the correct password (which derives a Key Encryption Key via Argon2id) **and** a successful TPM unseal operation. The password alone is insufficient, even if the KEK could be derived from it.

- **Tampered ciphertext**: File data is encrypted with AES-256-GCM; any modification to the ciphertext or tag is detected during decryption and fails authentication.

- **TPM fingerprint mismatch**: Each TPM has a unique Endorsement Key (EK) fingerprint. The container stores the fingerprint of the machine that encrypted the file, and decryption fails if the fingerprint does not match the current TPM. This check occurs before any TPM operation.

- **Side-channel leakage from key comparison**: The `verify_key()` function uses `hmac.compare_digest()` for constant-time comparison, preventing timing attacks based on key similarity.

## Explicit Limitations

- **Single-machine only**: Files encrypted on one machine cannot be decrypted on another, even with the same password and same TPM model. This limits portability and cross-device use. The DEK is sealed to the specific TPM hardware via `tr_set_auth` and TPM object attributes.

- **TPM failure loss**: If the TPM hardware fails, is replaced, or becomes inaccessible, the sealed DEK cannot be recovered. File contents are permanently lost. No backup or recovery mechanism is provided.

- **Password-only portability not supported**: Files are not portable across devices. If you need cross-device encryption, use GUN-101 (password-only mode) instead of GUN-101-TPM.

- **No key rotation**: The DEK is generated per-file and sealed to the TPM. Re-encrypting an existing file with a new password requires re-encrypting the entire file.

- **Argon2id parameters are fixed**: The Argon2id parameters (time cost, memory cost, parallelism) are compiled from config.py and cannot be overridden per-operation. This ensures consistent security but limits flexibility.

- **No forward secrecy**: If a password is compromised, all files encrypted with that password are compromised, regardless of TPM status. The TPM protects against pure-password attacks but not against a compromised password.

- **No integrity verification of sealed blob beyond TPM**: The TPM validates the sealed blob during unseal, but there is no additional out-of-band integrity check. Corrupted containers may cause TPM unseal to fail.

- **No warranty or guarantee**: This tool is provided as-is. The authors are not liable for data loss resulting from TPM failure, password loss, or any other cause.

- **Environment variable password exposure**: Using the `GUN101TPM_PASSWORD` environment variable is less secure — the password may appear in shell history or process listings. The CLI prints a visible warning when this path is used.

- **No quantum-resistant protection**: AES-256 provides ~128-bit post-quantum security; TPM sealing varies by vendor. For long-term archival, consider alternative approaches.