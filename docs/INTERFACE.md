# GUN-101-TPM Interface Reference

This document describes the external interfaces provided by GUN-101-TPM: the
`gun101tpm` command-line program and the Python functions used to encrypt and
decrypt file data.

## Command-line interface

The command-line program reads and writes local files. Passwords are requested
interactively unless the `GUN101TPM_PASSWORD` environment variable is set.

### Check TPM availability

```text
gun101tpm check-tpm
```

When a TPM 2.0 device is available, the command prints its diagnostic
fingerprint. If no device is available, it exits without printing a
fingerprint. The fingerprint is diagnostic output only and is not stored in
encrypted containers.

### Encrypt a file

```text
gun101tpm encrypt INPUT [--output OUTPUT]
```

`INPUT` must identify an existing readable file. On success, the command writes
the encrypted container to `INPUT.gun101`, unless `--output` specifies another
path, and prints the output path. Existing output files require confirmation.

### Decrypt a file

```text
gun101tpm decrypt INPUT [--output OUTPUT]
```

`INPUT` must identify an existing readable `.gun101` container. On success, the
command writes the recovered plaintext to the path without the `.gun101`
suffix, unless `--output` specifies another path, and prints the output path.
Existing output files require confirmation.

### Errors and exit status

- Exit status `0` indicates successful completion.
- Exit status `1` indicates a TPM, file, password, encryption, decryption, or
  output error. A diagnostic is printed to standard output.
- Invalid command-line syntax is handled by Python `argparse` and exits with
  status `2`.

Encrypted containers are UTF-8 JSON documents containing the protocol version,
hardware-binding mode, cipher selection, salt, sealed key blob, file nonce,
authentication tag, and ciphertext. Sensitive keys and passwords are not part
of the container. The default cipher is `AES-256-GCM`; the Python API also
supports the allowlisted `CHACHA20-POLY1305` algorithm through its optional
`algorithm` argument.

## Python interface

The data-processing functions are available from `gun101tpm.handler`:

```python
from gun101tpm.handler import decrypt_file, encrypt_file

encrypted = encrypt_file(file_data, password)
plaintext = decrypt_file(encrypted, password)
```

### `encrypt_file(file_data, password)`

- Input: `file_data` as `bytes` and `password` as a non-empty `str`.
- Output: UTF-8 encoded encrypted-container `bytes`.
- Errors: raises `ValueError` for invalid input or unsupported encryption
  conditions, and may propagate backend or cryptographic errors.

### `decrypt_file(encrypted_data, password)`

- Input: encrypted-container `bytes` and the password as a non-empty `str`.
- Output: recovered plaintext as `bytes`.
- Errors: raises `ValueError` for malformed containers, unsupported protocol
  versions, wrong passwords, unavailable hardware, corrupted data, or failed
  authentication.

The TPM backend is selected for the host platform. TPM-bound data is intended
to decrypt only on the machine whose hardware created the container, subject
to the backend limitations documented in the [README](../README.md) and
[security model](SECURITY.md).