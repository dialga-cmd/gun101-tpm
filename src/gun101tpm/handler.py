# Copyright (c) 2026 GUN-101-TPM contributors
# SPDX-License-Identifier: MIT
"""
Handler functions for GUN-101-TPM encryption/decryption.

Supports multiple hardware backends: Linux TPM 2.0, Windows TBS,
and macOS Secure Enclave (stub).
"""

from .config import (
    DEFAULT_CIPHER,
    PROTOCOL,
    SUPPORTED_CIPHERS,
    VERSION,
    DEK_LEN,
    SALT_LEN,
)
from .backends import unseal_from_tpm, get_backend
from .kdf import derive_key
from .cipher import encrypt as aes_encrypt, decrypt as aes_decrypt
import base64
import json
import secrets


def _clear_memory(data):
    """Securely clear sensitive data from memory when possible."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Convert to bytearray, clear, then let GC reclaim
        ba = bytearray(data)
        for i in range(len(ba)):
            ba[i] = 0


def encrypt_file(
    file_data: bytes,
    password: str,
    algorithm: str = DEFAULT_CIPHER,
) -> bytes:
    """
    Encrypt data using password-derived key wrapped with hardware binding.

    Supported backends:
    - Linux: TPM 2.0 hardware binding

    The resulting container includes a 'mode' field indicating the
    hardware binding method.
    """
    # Get the appropriate backend (auto-selects based on sys.platform)
    backend = get_backend()

    if not isinstance(file_data, bytes):
        raise ValueError("File data must be bytes")
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    if algorithm not in SUPPORTED_CIPHERS:
        raise ValueError(f"Unsupported cipher: {algorithm}")
    if len(file_data) > (1 << 30):  # 1 GiB limit
        raise ValueError("File too large (max 1 GiB)")

    # Generate a random salt for this encryption
    salt = secrets.token_bytes(SALT_LEN)

    # Generate a random Data Encryption Key (DEK)
    dek = secrets.token_bytes(DEK_LEN)  # 32 bytes for AES-256

    # Derive Key Encryption Key (KEK) from password using Argon2id
    kek = derive_key(password, salt)

    # Seal the raw DEK to the hardware module via the backend
    # This backend handles TPM, Keystore, etc. transparently
    sealed_blob = backend.seal(dek, kek)

    # Encrypt the file data with the DEK
    file_nonce, file_ciphertext, file_tag = aes_encrypt(file_data, dek, algorithm)

    # Clear sensitive keys from memory
    _clear_memory(bytearray(dek))
    _clear_memory(bytearray(kek))

    # Determine the mode from the backend type for container awareness
    backend_type = type(backend).__name__
    if "LinuxTPMBackend" in backend_type or "linux" in backend_type.lower():
        mode = "TPM"
    elif "WindowsTBSBackend" in backend_type or "windows" in backend_type.lower():
        mode = "TPM"
    else:
        mode = "Unknown"

    # The sealed blob is bound to this hardware module; do not expose
    # device identifiers in the container.
    container = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "cipher": algorithm,
        "mode": mode,  # TPM or Unknown
        "salt": base64.b64encode(salt).decode('utf-8'),
        "sealed_blob": base64.b64encode(sealed_blob).decode('utf-8'),
        "file_nonce": base64.b64encode(file_nonce).decode('utf-8'),
        "file_tag": base64.b64encode(file_tag).decode('utf-8'),
        "ciphertext": base64.b64encode(file_ciphertext).decode('utf-8')
    }
    # Explicitly ensure no KEK-encrypted DEK fields leak into the container
    for field in ("dek_nonce", "dek_ciphertext", "dek_tag"):
        container.pop(field, None)

    # Convert to JSON and encode
    json_data = json.dumps(container, separators=(',', ':'))  # Compact JSON
    return json_data.encode('utf-8')


def decrypt_file(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt data using password-derived key unwrapped from hardware sealing.

    Supported backends:
    - Linux: TPM 2.0 hardware binding

    The password-derived KEK is presented as the hardware module's
    auth value, so both the password AND the hardware module are required.
    """
    # Validate inputs
    if not isinstance(encrypted_data, bytes):
        raise ValueError("Encrypted data must be bytes")
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")

    # Parse JSON container
    try:
        container = json.loads(encrypted_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError("Invalid container format") from e
    if not isinstance(container, dict):
        raise ValueError("Invalid container format")

    # Verify protocol and version
    if container.get("protocol") != PROTOCOL:
        raise ValueError(f"Unsupported protocol: {container.get('protocol')}")
    if container.get("version") != VERSION:
        raise ValueError(f"Unsupported version: {container.get('version')}")
    algorithm = container.get("cipher", DEFAULT_CIPHER)
    if algorithm not in SUPPORTED_CIPHERS:
        raise ValueError(f"Unsupported cipher: {algorithm}")

    # Extract fields first (needed for both modes)
    try:
        encoded_fields = (
            'salt', 'sealed_blob', 'file_nonce', 'file_tag', 'ciphertext'
        )
        if any(not isinstance(container[field], str) for field in encoded_fields):
            raise ValueError("Container fields must be base64 strings")
        salt = base64.b64decode(container['salt'], validate=True)
        sealed_blob = base64.b64decode(container['sealed_blob'], validate=True)
        file_nonce = base64.b64decode(container['file_nonce'], validate=True)
        file_tag = base64.b64decode(container['file_tag'], validate=True)
        ciphertext = base64.b64decode(container['ciphertext'], validate=True)
        if not sealed_blob:
            raise ValueError("Sealed blob must not be empty")
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError("Failed to decode container fields") from e

    # Derive KEK from password using Argon2id (used as hardware auth value)
    kek = derive_key(password, salt)

    # Unseal the DEK from the hardware module via the backend
    # The password-derived KEK is presented as the hardware auth value,
    # so both the password AND the hardware module are required.
    try:
        dek = unseal_from_tpm(sealed_blob, kek)
    except ValueError as e:
        _clear_memory(bytearray(kek))
        raise ValueError(
            "TPM unseal failed. Wrong machine, wrong password, or corrupted data."
        ) from e

    # Clear KEK from memory
    _clear_memory(bytearray(kek))

    # Decrypt the file data with the DEK
    try:
        plaintext = aes_decrypt(file_nonce, ciphertext, file_tag, dek, algorithm)
    except ValueError as e:
        _clear_memory(bytearray(dek))
        raise ValueError("Decryption failed. Data may be corrupted.") from e

    # Clear DEK from memory
    _clear_memory(bytearray(dek))

    return plaintext