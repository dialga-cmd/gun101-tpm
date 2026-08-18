import sys
from unittest.mock import patch
import pytest


def test_platform_check_linux():
    """On Linux, platform check passes and functions work normally."""
    # Import after patching platform
    with patch('sys.platform', 'Linux'):
        from gun101tpm.tpm import _check_platform_supported
        _check_platform_supported()


def test_platform_check_windows():
    """On Windows, _check_platform_supported() raises RuntimeError."""
    with patch('sys.platform', 'Windows'):
        from gun101tpm.tpm import _check_platform_supported
        with pytest.raises(RuntimeError, match="GUN-101-TPM is currently Linux-only"):
            _check_platform_supported()


def test_platform_check_darwin():
    """On Darwin/macOS, _check_platform_supported() raises RuntimeError."""
    with patch('sys.platform', 'Darwin'):
        from gun101tpm.tpm import _check_platform_supported
        with pytest.raises(RuntimeError, match="GUN-101-TPM is currently Linux-only"):
            _check_platform_supported()


def test_check_tpm_available_windows():
    """check_tpm_available() raises RuntimeError on Windows."""
    with patch('sys.platform', 'Windows'):
        from gun101tpm.tpm import check_tpm_available
        with pytest.raises(RuntimeError, match="GUN-101-TPM is currently Linux-only"):
            check_tpm_available()


def test_seal_to_tpm_windows():
    """seal_to_tpm() raises RuntimeError on Windows."""
    with patch('sys.platform', 'Windows'):
        from gun101tpm.tpm import seal_to_tpm
        # seal_to_tpm calls _check_platform_supported() before import,
        # so it should raise RuntimeError
        try:
            seal_to_tpm(b"test", b"pass")
            pytest.fail("Expected RuntimeError")
        except RuntimeError as e:
            assert "GUN-101-TPM is currently Linux-only" in str(e)


def test_unseal_from_tpm_darwin():
    """unseal_from_tpm() raises RuntimeError on Darwin."""
    with patch('sys.platform', 'Darwin'):
        from gun101tpm.tpm import unseal_from_tpm
        try:
            unseal_from_tpm(b"test", b"pass")
            pytest.fail("Expected RuntimeError")
        except RuntimeError as e:
            assert "GUN-101-TPM is currently Linux-only" in str(e)
