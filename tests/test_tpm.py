"""
Real, un-mocked integration tests for GUN-101-TPM operations (Linux TPM 2.0).

These tests run directly against the system's TPM 2.0 device (e.g. /dev/tpm0, /dev/tpmrm0 or swtpm).
No mocks are used. If TPM 2.0 hardware/driver is missing or inaccessible, tests will fail
with the actual hardware/system error.
"""

import json
import base64
import pytest

from gun101tpm.handler import encrypt_file, decrypt_file
from gun101tpm.backends import check_tpm_available, get_tpm_fingerprint
from gun101tpm.config import PROTOCOL, VERSION


def test_tpm_hardware_available():
    """Verify that a real TPM 2.0 device is present and accessible on Linux."""
    assert check_tpm_available() is True, "TPM 2.0 hardware device not found or inaccessible on Linux."


def test_get_real_tpm_fingerprint():
    """Verify reading EK fingerprint from real TPM 2.0 hardware."""
    fingerprint = get_tpm_fingerprint()
    assert isinstance(fingerprint, str)
    assert len(fingerprint.split(":")) == 32, f"Invalid TPM fingerprint format: {fingerprint}"


def test_real_encrypt_decrypt_roundtrip():
    """Test full encryption and decryption lifecycle on real TPM 2.0 hardware."""
    original_data = b"Confidential document content to seal with real TPM 2.0"
    password = "super-secure-password-123!"

    # Encrypt
    encrypted_container_bytes = encrypt_file(original_data, password)
    assert isinstance(encrypted_container_bytes, bytes)

    # Validate container format
    container = json.loads(encrypted_container_bytes.decode('utf-8'))
    assert container["protocol"] == PROTOCOL
    assert container["version"] == VERSION
    assert "sealed_blob" in container
    assert "ciphertext" in container

    # Decrypt
    decrypted_data = decrypt_file(encrypted_container_bytes, password)
    assert decrypted_data == original_data


def test_real_decrypt_wrong_password_fails():
    """Test that decryption with incorrect password fails on real TPM hardware."""
    original_data = b"Sensitive payload"
    password_correct = "correct_password_99"
    password_wrong = "wrong_password_00"

    encrypted_bytes = encrypt_file(original_data, password_correct)

    with pytest.raises(ValueError, match="TPM unseal failed"):
        decrypt_file(encrypted_bytes, password_wrong)


def test_real_decrypt_corrupted_blob_fails():
    """Test that tampered sealed blob fails during unseal on real TPM hardware."""
    original_data = b"Payload for tamper test"
    password = "password123"

    encrypted_bytes = encrypt_file(original_data, password)
    container = json.loads(encrypted_bytes.decode('utf-8'))

    # Corrupt the sealed blob
    raw_sealed = base64.b64decode(container['sealed_blob'])
    corrupted_sealed = bytes([b ^ 0xFF for b in raw_sealed])
    container['sealed_blob'] = base64.b64encode(corrupted_sealed).decode('utf-8')

    corrupted_container_bytes = json.dumps(container).encode('utf-8')

    with pytest.raises(ValueError, match="TPM unseal failed"):
        decrypt_file(corrupted_container_bytes, password)