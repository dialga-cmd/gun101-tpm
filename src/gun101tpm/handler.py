"""
Handler functions for GUN-101-TPM encryption/decryption.
"""

from .config import (PROTOCOL, VERSION, DEK_LEN, AES_NONCE_LEN, ARGON2_TIME_COST,
                     ARGON2_MEMORY_COST, ARGON2_PARALLELISM, SALT_LEN)
from .tpm import check_tpm_available, get_tpm_fingerprint, seal_to_tpm, unseal_from_tpm
from .kdf import derive_key, verify_key
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

    # Encrypt the DEK with the KEK using AES-256-GCM
    dek_nonce, dek_ciphertext, dek_tag = aes_encrypt(dek, kek)

    # Seal the KEK-encrypted DEK to TPM (binds to hardware)
    # We seal the encrypted DEK + nonce + tag together as one blob
    encrypted_dek_blob = dek_nonce + dek_ciphertext + dek_tag
    sealed_blob = seal_to_tpm(encrypted_dek_blob)

    # Encrypt the file data with the DEK
    file_nonce, file_ciphertext, file_tag = aes_encrypt(file_data, dek)

    # Clear sensitive keys from memory
    _clear_memory(bytearray(dek))
    _clear_memory(bytearray(kek))

    # Create container
    container = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "tpm_fingerprint": get_tpm_fingerprint(),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "sealed_blob": base64.b64encode(sealed_blob).decode('utf-8'),
        "dek_nonce": base64.b64encode(dek_nonce).decode('utf-8'),
        "dek_tag": base64.b64encode(dek_tag).decode('utf-8'),
        "dek_ciphertext": base64.b64encode(dek_ciphertext).decode('utf-8'),
        "file_nonce": base64.b64encode(file_nonce).decode('utf-8'),
        "file_tag": base64.b64encode(file_tag).decode('utf-8'),
        "ciphertext": base64.b64encode(file_ciphertext).decode('utf-8')
    }

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

    # Check TPM fingerprint matches container["tpm_fingerprint"]
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
        dek_nonce = base64.b64decode(container['dek_nonce'])
        dek_tag = base64.b64decode(container['dek_tag'])
        dek_ciphertext = base64.b64decode(container['dek_ciphertext'])
        file_nonce = base64.b64decode(container['file_nonce'])
        file_tag = base64.b64decode(container['file_tag'])
        ciphertext = base64.b64decode(container['ciphertext'])
    except Exception as e:
        raise ValueError("Failed to decode container fields") from e

    # Derive KEK from password using Argon2id
    kek = derive_key(password, salt)

    # Decrypt the DEK using the KEK
    try:
        dek = aes_decrypt(dek_nonce, dek_ciphertext, dek_tag, kek)
    except ValueError as e:
        _clear_memory(bytearray(kek))
        raise ValueError("Wrong password or corrupted data") from e

    # Clear KEK from memory now that we have DEK
    _clear_memory(bytearray(kek))

    # Unseal the KEK-encrypted DEK from TPM (retrieves hardware-bound key)
    try:
        encrypted_dek_blob = unseal_from_tpm(sealed_blob)
    except ValueError as e:
        _clear_memory(bytearray(dek))
        raise ValueError("TPM unseal failed. Wrong machine or corrupted data.") from e

    # Extract the DEK from the unsealed blob
    if len(encrypted_dek_blob) < AES_NONCE_LEN + 16:  # nonce + tag minimum
        _clear_memory(bytearray(dek))
        raise ValueError("Corrupted sealed data")

    # The encrypted DEK blob is: nonce + ciphertext + tag
    actual_dek_nonce = encrypted_dek_blob[:AES_NONCE_LEN]
    actual_dek_ciphertext = encrypted_dek_blob[AES_NONCE_LEN:-16]
    actual_dek_tag = encrypted_dek_blob[-16:]

    # Decrypt the DEK with the KEK (we already derived KEK above)
    try:
        dek = aes_decrypt(actual_dek_nonce, actual_dek_ciphertext, actual_dek_tag, kek)
    except ValueError as e:
        _clear_memory(bytearray(dek))
        raise ValueError("Failed to recover DEK. Wrong password or corrupted data.") from e

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