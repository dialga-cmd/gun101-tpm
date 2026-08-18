"""
Key Derivation Function using Argon2id for GUN-101-TPM.
"""
import hmac
import argon2
from .config import ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM, SALT_LEN

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from password and salt using Argon2id.

    Args:
        password: The password string
        salt: Salt bytes (should be SALT_LEN bytes)

    Returns:
        32-byte derived key
    """
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be exactly {SALT_LEN} bytes")

    hasher = argon2.PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,  # 256-bit key
        salt_len=SALT_LEN,
        type=argon2.Type.ID  # Argon2id
    )

    # Argon2 expects the password as bytes
    password_bytes = password.encode('utf-8')

    # Hash the password with the salt
    hash_result = hasher.hash(password_bytes, salt=salt)

    # Extract the hash portion (remove the identifier and parameters)
    # Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    # We want just the hash part at the end
    hash_b64 = hash_result.split('$')[-1]

    # Decode from base64 to get raw bytes
    import base64
    # Add padding if needed
    missing_padding = len(hash_b64) % 4
    if missing_padding:
        hash_b64 += '=' * (4 - missing_padding)

    key = base64.b64decode(hash_b64)

    # Ensure we have exactly 32 bytes
    if len(key) != 32:
        # If not 32 bytes, derive again with truncation/extension
        hasher2 = argon2.PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=32,
            salt_len=SALT_LEN,
            type=argon2.Type.ID
        )
        hash_result2 = hasher2.hash(password_bytes, salt=salt)
        hash_b64_2 = hash_result2.split('$')[-1]
        missing_padding_2 = len(hash_b64_2) % 4
        if missing_padding_2:
            hash_b64_2 += '=' * (4 - missing_padding_2)
        key = base64.b64decode(hash_b64_2)

    return key
def verify_key(password: str, salt: bytes, expected_key: bytes) -> bool:
    """
    Verify that a password derives to the expected key.

    Args:
        password: The password string
        salt: Salt bytes
        expected_key: Expected 32-byte key

    Returns:
        True if password derives to expected_key
    """
    try:
        derived_key = derive_key(password, salt)
        # Constant-time comparison to avoid timing attacks
        return hmac.compare_digest(derived_key, expected_key)
    except Exception:
        return False


# _constant_time_compare removed — deprecated; hmac.compare_digest() is the
# standard constant-time comparison. verify_key() now uses
# hmac.compare_digest() directly (was already doing so).