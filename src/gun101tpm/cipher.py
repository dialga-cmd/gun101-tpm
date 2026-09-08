# Copyright (c) 2026 GUN-101-TPM contributors
# SPDX-License-Identifier: MIT

"""
AES-256-GCM encryption and decryption for GUN-101-TPM.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .config import AES_NONCE_LEN, DEFAULT_CIPHER, SUPPORTED_CIPHERS

def encrypt(
    plaintext: bytes,
    key: bytes,
    algorithm: str = DEFAULT_CIPHER,
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns a tuple (nonce, ciphertext, tag).
    The nonce is generated randomly of length AES_NONCE_LEN.
    The key must be 32 bytes (AES-256).
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if algorithm not in SUPPORTED_CIPHERS:
        raise ValueError(f"Unsupported cipher: {algorithm}")
    import os
    nonce = os.urandom(AES_NONCE_LEN)
    cipher = AESGCM(key) if algorithm == "AES-256-GCM" else ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    # AESGCM.encrypt returns ciphertext + tag concatenated.
    # The tag is the last 16 bytes.
    ciphertext_only = ciphertext[:-16]
    tag = ciphertext[-16:]
    return nonce, ciphertext_only, tag

def decrypt(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    key: bytes,
    algorithm: str = DEFAULT_CIPHER,
) -> bytes:
    """
    Decrypt ciphertext with AES-256-GCM.
    Returns the plaintext.
    nonce: AES_NONCE_LEN bytes
    ciphertext: the encrypted bytes (without tag)
    tag: 16 bytes authentication tag
    key: 32 bytes
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if algorithm not in SUPPORTED_CIPHERS:
        raise ValueError(f"Unsupported cipher: {algorithm}")
    if len(nonce) != AES_NONCE_LEN:
        raise ValueError(f"Nonce must be {AES_NONCE_LEN} bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    cipher = AESGCM(key) if algorithm == "AES-256-GCM" else ChaCha20Poly1305(key)
    # Combine ciphertext and tag
    combined = ciphertext + tag
    try:
        plaintext = cipher.decrypt(nonce, combined, None)
    except Exception as e:
        raise ValueError("Decryption failed") from e
    return plaintext