"""
Real, un-mocked integration tests for Windows TBS (TPM Base Services) backend.

These tests run directly against native Windows tbs.dll and TPM 2.0 hardware on Windows.
No mocks are used.
"""

import sys
import pytest

from gun101tpm.backends.windows import WindowsTBSBackend


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS real tests require running natively on Windows OS.")
def test_windows_real_tpm_available():
    """Verify that a real TPM 2.0 device is accessible via Windows TBS API."""
    backend = WindowsTBSBackend()
    assert backend.check_available() is True, "TPM 2.0 device unavailable via Windows TBS API (tbs.dll)."


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS real tests require running natively on Windows OS.")
def test_windows_real_get_fingerprint():
    """Verify obtaining EK fingerprint from real Windows TPM 2.0 hardware."""
    backend = WindowsTBSBackend()
    fingerprint = backend.get_fingerprint()
    assert isinstance(fingerprint, str)
    assert len(fingerprint.split(":")) == 32, f"Invalid Windows TPM fingerprint format: {fingerprint}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS real tests require running natively on Windows OS.")
def test_windows_real_seal_unseal_roundtrip():
    """Test sealing and unsealing secret data on real Windows TPM hardware."""
    backend = WindowsTBSBackend()
    secret = b"windows_real_tpm_secret_key_32_bytes!!"
    password_auth = b"argon2id_derived_kek_auth_bytes"

    sealed_blob = backend.seal(secret, password_auth)
    assert isinstance(sealed_blob, bytes)
    assert len(sealed_blob) > len(secret)

    unsealed_secret = backend.unseal(sealed_blob, password_auth)
    assert unsealed_secret == secret


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS real tests require running natively on Windows OS.")
def test_windows_real_unseal_wrong_password_fails():
    """Test that unsealing with incorrect password auth fails on real Windows TPM."""
    backend = WindowsTBSBackend()
    secret = b"windows_secret_payload"
    auth_correct = b"correct_auth_val"
    auth_wrong = b"wrong_auth_val"

    sealed_blob = backend.seal(secret, auth_correct)
    with pytest.raises(ValueError, match="TPM unseal failed"):
        backend.unseal(sealed_blob, auth_wrong)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows TBS real tests require running natively on Windows OS.")
def test_windows_real_unseal_corrupted_blob_fails():
    """Test that unsealing corrupted sealed blob fails on real Windows TPM."""
    backend = WindowsTBSBackend()
    secret = b"windows_secret_payload"
    auth = b"auth_val"

    sealed_blob = backend.seal(secret, auth)
    corrupted_blob = b"CORRUPTED_HEADER" + sealed_blob[16:]

    with pytest.raises(ValueError, match="Invalid sealed blob"):
        backend.unseal(corrupted_blob, auth)
