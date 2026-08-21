"""
Handler functions for GUN-101-TPM encryption/decryption.
"""

from .config import (PROTOCOL, VERSION, DEK_LEN, AES_NONCE_LEN, ARGON2_TIME_COST,
                     ARGON2_MEMORY_COST, ARGON2_PARALLELISM, SALT_LEN)
from .backends import check_tpm_available, get_tpm_fingerprint, seal_to_tpm, unseal_from_tpm
from .kdf import derive_key
from .cipher import encrypt as aes_encrypt, decrypt as aes_decrypt
import base64
import json
import hashlib
import secrets
import os

KDF_CACHE = {}

def _clear_memory(data):
    """Securely clear sensitive data from memory when possible."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Bytes are immutable, but we can overwrite reference
        pass  # Python's garbage collector will handle this eventually

def encrypt_file(file_data: bytes, password: str) -> bytes:
    """
    Encrypt data using password-derived key wrapped with TPM sealing.
    """
    # Check TPM available
    if not check_tpm_available():
        raise RuntimeError(
            "TPM 2.0 device not found. Please ensure TPM 2.0 is available and "
            "tpm2-pytss is installed. See docs/TPM_SETUP.md for setup instructions."
        )

    # Validate inputs
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string")
    if len(file_data) > (1 << 30):  # 1 GiB limit
        raise ValueError("File too large (max 1 GiB)")

    # Generate a random salt for this encryption
    salt = secrets.token_bytes(SALT_LEN)

    # Generate a random Data Encryption Key (DEK)
    dek = secrets.token_bytes(DEK_LEN)  # 32 bytes for AES-256

    # Derive Key Encryption Key (KEK) from password using Argon2id
    kek = derive_key(password, salt)

    # Seal the raw DEK to TPM with password-derived auth
    sealed_blob = seal_to_tpm(dek, kek)

    # Encrypt the file data with the DEK
    file_nonce, file_ciphertext, file_tag = aes_encrypt(file_data, dek)

    # Clear sensitive keys from memory
    _clear_memory(bytearray(dek))
    _clear_memory(bytearray(kek))

    # The sealed blob is already bound to this TPM; do not expose a device
    # identifier in the container.
    container = {
        "protocol": PROTOCOL,
        "version": VERSION,
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
    Decrypt data using password-derived key unwrapped from TPM sealing.
    """
    # Check TPM available
    if not check_tpm_available():
        raise RuntimeError(
            "TPM 2.0 device not found. Please ensure TPM 2.0 is available and "
            "tpm2-pytss is installed. See docs/TPM_SETUP.md for setup instructions."
        )

    # Validate inputs
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string")

    # Parse JSON container
    try:
        container = json.loads(encrypted_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError("Invalid container format") from e

    # Verify protocol and version
    if container.get("protocol") != PROTOCOL:
        raise ValueError(f"Unsupported protocol: {container.get('protocol')}")
    if container.get("version") != VERSION:
        raise ValueError(f"Unsupported version: {container.get('version')}")

    # Older containers exposed a fingerprint. Keep reading it for backwards
    # compatibility, but never include one in newly encrypted containers.
    if "tpm_fingerprint_hash" in container:
        current_fingerprint = get_tpm_fingerprint()
        if container["tpm_fingerprint_hash"] != hashlib.sha256(current_fingerprint.encode('utf-8')).hexdigest():
            raise ValueError(
                "This file was encrypted on a different machine and cannot be decrypted here. "
                "GUN-101-TPM files are hardware-bound."
            )
    elif "tpm_fingerprint" in container:
        current_fingerprint = get_tpm_fingerprint()
        if container["tpm_fingerprint"] != current_fingerprint:
            raise ValueError(
                "This file was encrypted on a different machine and cannot be decrypted here. "
                "GUN-101-TPM files are hardware-bound."
            )
    # Extract fields
    try:
        salt = base64.b64decode(container['salt'])
        sealed_blob = base64.b64decode(container['sealed_blob'])
        file_nonce = base64.b64decode(container['file_nonce'])
        file_tag = base64.b64decode(container['file_tag'])
        ciphertext = base64.b64decode(container['ciphertext'])
    except Exception as e:
        raise ValueError("Failed to decode container fields") from e

    # Derive KEK from password using Argon2id (used as TPM auth value)
    kek = derive_key(password, salt)

    # Unseal the DEK from TPM — the ONLY way to obtain the DEK.
    # The password-derived KEK is presented as the TPM object auth value,
    # so both the password AND the TPM are required.
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
        plaintext = aes_decrypt(file_nonce, ciphertext, file_tag, dek)
    except ValueError as e:
        _clear_memory(bytearray(dek))
        raise ValueError("Decryption failed. Data may be corrupted.") from e

    # Clear DEK from memory
    _clear_memory(bytearray(dek))

    return plaintext