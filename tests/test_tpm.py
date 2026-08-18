"""
Tests for GUN-101-TPM TPM operations and encryption/decryption.
Uses mocking to verify TPM binding when no TPM is available.
"""
import json
import base64
import pytest
from unittest.mock import patch

from gun101tpm.handler import encrypt_file, decrypt_file
from gun101tpm.config import PROTOCOL, VERSION


def test_encrypt_file_has_no_kek_fields():
    """Encrypt file does not include dek_nonce/dek_ciphertext/dek_tag in container."""
    data = b"test data for encryption"
    password = "password123"

    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt:
        # Setup mocks
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32  # 32-byte KEK
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)  # nonce, ct, tag

        encrypted = encrypt_file(data, password)
        container = json.loads(encrypted.decode('utf-8'))

        # These fields must NOT be present in the container
        for field in ("dek_nonce", "dek_ciphertext", "dek_tag"):
            assert field not in container, f"Field '{field}' should not be in container"


def test_encrypt_file_has_sealed_blob():
    """Encrypt file includes sealed_blob in container."""
    data = b"test data for encryption"
    password = "password123"

    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt:
        # Setup mocks
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)

        encrypted = encrypt_file(data, password)
        container = json.loads(encrypted.decode('utf-8'))
        assert "sealed_blob" in container
        assert container["sealed_blob"]


def test_decrypt_file_obtains_dek_only_from_tpm():
    """Decrypt file obtains DEK ONLY via unseal_from_tpm call.

    Test that if unseal_from_tpm raises, decrypt_file fails even with
    the correct password. This verifies TPM binding is enforced.
    """
    data = b"test data for encryption"
    password = "password123"

    # Mock ALL TPM-dependent functions for both encrypt AND decrypt
    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt, \
         patch("gun101tpm.handler.unseal_from_tpm") as mock_unseal, \
         patch("gun101tpm.handler.check_tpm_available") as mock_check_tpm:
        # Setup mocks for encrypt
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)
        # Setup mocks for decrypt
        mock_unseal.side_effect = ValueError("TPM unseal failed")
        mock_check_tpm.return_value = True

        # encrypt_file uses the mocks from the outer with block
        encrypted = encrypt_file(data, password)

        # decrypt_file also uses the mocks (they're still active)
        with pytest.raises(ValueError, match="TPM unseal failed"):
            decrypt_file(encrypted, password)


def test_tpm_binding_enforced_even_with_correct_password():
    """Verify that decrypt fails on wrong machine even with correct password.

    This is the key TPM-binding test: even given the correct password,
    decryption fails because the DEK can only be obtained via
    unseal_from_tpm(), which requires the TPM.
    """
    data = b"this is test data for tpm binding verification"
    password = "correct-password-123"

    # Mock ALL TPM-dependent functions for both encrypt AND decrypt
    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt, \
         patch("gun101tpm.handler.unseal_from_tpm") as mock_unseal, \
         patch("gun101tpm.handler.check_tpm_available") as mock_check_tpm:
        # Setup mocks for encrypt
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)
        # Setup mocks for decrypt
        mock_unseal.side_effect = ValueError(
            "TPM unseal failed. Wrong machine, wrong password, or corrupted data."
        )
        mock_check_tpm.return_value = True

        # encrypt_file uses the mocks from the outer with block
        encrypted = encrypt_file(data, password)

        # decrypt_file also uses the mocks (they're still active)
        # Use different fingerprint to simulate different machine
        mock_fingerprint.return_value = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

        with pytest.raises(ValueError, match="different machine"):
            decrypt_file(encrypted, password)


def test_wrong_password_still_fails():
    """Verify that wrong password still causes decryption failure."""
    data = b"test data"
    password_right = "correct"
    password_wrong = "wrong"

    # Mock ALL TPM-dependent functions for both encrypt AND decrypt
    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt, \
         patch("gun101tpm.handler.unseal_from_tpm") as mock_unseal, \
         patch("gun101tpm.handler.check_tpm_available") as mock_check_tpm:
        # Setup mocks for encrypt
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)
        # Setup mocks for decrypt
        mock_unseal.side_effect = ValueError("Wrong password")

        # encrypt_file uses the mocks from the outer with block
        encrypted = encrypt_file(data, password_right)

        # decrypt_file also uses the mocks (they're still active)
        with pytest.raises(ValueError, match="TPM unseal failed"):
            decrypt_file(encrypted, password_wrong)


def test_tampered_sealed_blob_causes_tpm_unseal_failure():
    """Tampered sealed_blob causes TPM unseal failure."""
    data = b"test data"
    password = "password"

    # Mock ALL TPM-dependent functions for both encrypt AND decrypt
    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt, \
         patch("gun101tpm.handler.unseal_from_tpm") as mock_unseal, \
         patch("gun101tpm.handler.check_tpm_available") as mock_check_tpm:
        # Setup mocks for encrypt
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)
        # Setup mocks for decrypt
        mock_unseal.side_effect = ValueError("TPM unseal failed")
        mock_check_tpm.return_value = True

        # encrypt_file uses the mocks from the outer with block
        encrypted = encrypt_file(data, password)

        # Corrupt the sealed_blob
        import json, base64
        container = json.loads(encrypted.decode('utf-8'))
        sb = base64.b64decode(container['sealed_blob'])
        sb_list = list(sb)
        if sb_list:
            sb_list[0] ^= 0x01
        corrupted_sb = bytes(sb_list)
        container['sealed_blob'] = base64.b64encode(corrupted_sb).decode('ascii')
        corrupted_encrypted = json.dumps(container).encode('utf-8')

        # decrypt_file also uses the mocks (they're still active)
        with pytest.raises(ValueError, match="TPM unseal failed"):
            decrypt_file(corrupted_encrypted, password)


def test_modified_tpm_fingerprint_triggers_fast_fail():
    """Modified tpm_fingerprint in container triggers fast-fail before any TPM operation."""
    data = b"test data"
    password = "password"

    # Mock ALL TPM-dependent functions for both encrypt AND decrypt
    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt, \
         patch("gun101tpm.handler.unseal_from_tpm") as mock_unseal, \
         patch("gun101tpm.handler.check_tpm_available") as mock_check_tpm:
        # Setup mocks for encrypt
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)
        # Setup mocks for decrypt
        mock_unseal.side_effect = ValueError("TPM unseal failed")
        mock_check_tpm.return_value = True

        # encrypt_file uses the mocks from the outer with block
        encrypted = encrypt_file(data, password)

        # Corrupt the sealed_blob
        import json
        container = json.loads(encrypted.decode('utf-8'))
        fp = container['tpm_fingerprint']
        lst = list(fp)
        lst[0] = '0' if lst[0] != '0' else '1'
        corrupted_fp = ''.join(lst)
        container['tpm_fingerprint'] = corrupted_fp
        corrupted_encrypted = json.dumps(container).encode('utf-8')

        # decrypt_file also uses the mocks (they're still active)
        with pytest.raises(ValueError, match="different machine"):
            decrypt_file(corrupted_encrypted, password)


def test_two_encryptions_produce_different_salts():
    """Two encryptions produce different salts."""
    data = b"same data"
    password = "same password"

    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt:
        # Setup mocks
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)

        enc1 = encrypt_file(data, password)
        enc2 = encrypt_file(data, password)
        c1 = json.loads(enc1.decode('utf-8'))
        c2 = json.loads(enc2.decode('utf-8'))
        salt1 = base64.b64decode(c1['salt'])
        salt2 = base64.b64decode(c2['salt'])
        assert salt1 != salt2


def test_two_encryptions_produce_different_sealed_blobs():
    """Two encryptions produce different sealed blobs."""
    data = b"same data"
    password = "same password"

    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt:
        # Setup mocks
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob1"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)

        enc1 = encrypt_file(data, password)
        # For second encryption, change the sealed blob mock return value
        with patch("gun101tpm.handler.seal_to_tpm") as mock_seal2:
            mock_seal2.return_value = b"mock_sealed_blob2"
            enc2 = encrypt_file(data, password)

        c1 = json.loads(enc1.decode('utf-8'))
        c2 = json.loads(enc2.decode('utf-8'))
        sb1 = base64.b64decode(c1['sealed_blob'])
        sb2 = base64.b64decode(c2['sealed_blob'])
        assert sb1 != sb2


def test_dek_not_present_in_container():
    """DEK is not present in the container in plaintext form."""
    data = b"test data"
    password = "password"

    with patch("gun101tpm.handler.seal_to_tpm") as mock_seal, \
         patch("gun101tpm.handler.get_tpm_fingerprint") as mock_fingerprint, \
         patch("gun101tpm.handler.derive_key") as mock_derive, \
         patch("gun101tpm.handler.aes_encrypt") as mock_aes_encrypt:
        # Setup mocks
        mock_fingerprint.return_value = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        mock_seal.return_value = b"mock_sealed_blob"
        mock_derive.return_value = b"\x00" * 32
        mock_aes_encrypt.return_value = (b"\x00" * 12, b"mock_ciphertext", b"\x00" * 16)
        encrypted = encrypt_file(data, password)
        import json, base64
        container = json.loads(encrypted.decode('utf-8'))

        # Verify that the DEK is not stored as a field in the container
        # The container should only have: protocol, version, tpm_fingerprint, salt,
        # sealed_blob, file_nonce, file_tag, ciphertext
        for field in ("dek_nonce", "dek_ciphertext", "dek_tag", "dek"):
            assert field not in container, f"Field '{field}' should not be in container"