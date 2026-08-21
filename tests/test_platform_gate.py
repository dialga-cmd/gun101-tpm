"""
Tests for platform backend selection and gating.

Verifies that the backend registry selects the correct backend
for each platform and that stub backends raise NotImplementedError.
"""
import os
import sys

# Ensure src directory is in sys.path for test discovery on Windows/Linux
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from unittest.mock import patch
import pytest

from gun101tpm.backends import get_backend, reset_backend
from gun101tpm.backends.linux import LinuxTPMBackend, _check_platform_supported
from gun101tpm.backends.windows import WindowsTBSBackend
from gun101tpm.backends.macos import MacOSSecureEnclaveBackend


@pytest.fixture(autouse=True)
def _reset_backend_singleton():
    """Reset the backend singleton before and after each test."""
    reset_backend()
    yield
    reset_backend()


# ── Linux platform check (defense-in-depth inside the Linux backend) ──

def test_platform_check_linux():
    """On Linux, platform check passes and functions work normally."""
    with patch('sys.platform', 'linux'):
        _check_platform_supported()


def test_platform_check_linux2():
    """On linux2, platform check also passes."""
    with patch('sys.platform', 'linux2'):
        _check_platform_supported()


def test_platform_check_non_linux_raises():
    """On non-Linux, _check_platform_supported() raises RuntimeError."""
    with patch('sys.platform', 'win32'):
        with pytest.raises(RuntimeError, match="Linux-only"):
            _check_platform_supported()


# ── Backend selection ──

def test_backend_selection_linux():
    """On Linux, get_backend() returns LinuxTPMBackend."""
    with patch('sys.platform', 'linux'):
        backend = get_backend()
        assert isinstance(backend, LinuxTPMBackend)


def test_backend_selection_win32():
    """On win32, get_backend() returns WindowsTBSBackend."""
    with patch('sys.platform', 'win32'):
        backend = get_backend()
        assert isinstance(backend, WindowsTBSBackend)


def test_backend_selection_darwin():
    """On darwin, get_backend() returns MacOSSecureEnclaveBackend."""
    with patch('sys.platform', 'darwin'):
        backend = get_backend()
        assert isinstance(backend, MacOSSecureEnclaveBackend)


def test_backend_selection_unsupported():
    """On an unsupported platform, get_backend() raises RuntimeError."""
    with patch('sys.platform', 'freebsd'):
        with pytest.raises(RuntimeError, match="Unsupported platform"):
            get_backend()


# ── Windows TBS backend ──

def test_windows_check_available_without_tbs():
    """WindowsTBSBackend.check_available() returns False without active tbs.dll."""
    backend = WindowsTBSBackend()
    assert backend.check_available() is False


def test_windows_seal_without_tbs():
    """WindowsTBSBackend.seal() raises RuntimeError without active tbs.dll."""
    backend = WindowsTBSBackend()
    with pytest.raises(RuntimeError, match="unavailable on Windows TBS"):
        backend.seal(b"test", b"pass")


def test_windows_unseal_without_tbs():
    """WindowsTBSBackend.unseal() raises RuntimeError without active tbs.dll."""
    backend = WindowsTBSBackend()
    with pytest.raises(RuntimeError, match="unavailable on Windows TBS"):
        backend.unseal(b"test", b"pass")


# ── macOS stub backend ──

def test_macos_check_available_not_implemented():
    """MacOSSecureEnclaveBackend.check_available() raises NotImplementedError."""
    backend = MacOSSecureEnclaveBackend()
    with pytest.raises(NotImplementedError, match="macOS Secure Enclave backend"):
        backend.check_available()


def test_macos_seal_not_implemented():
    """MacOSSecureEnclaveBackend.seal() raises NotImplementedError."""
    backend = MacOSSecureEnclaveBackend()
    with pytest.raises(NotImplementedError, match="macOS Secure Enclave backend"):
        backend.seal(b"test", b"pass")


def test_macos_unseal_not_implemented():
    """MacOSSecureEnclaveBackend.unseal() raises NotImplementedError."""
    backend = MacOSSecureEnclaveBackend()
    with pytest.raises(NotImplementedError, match="macOS Secure Enclave backend"):
        backend.unseal(b"test", b"pass")


# ── Convenience function delegation (through tpm.py backward compat shim) ──

def test_tpm_shim_check_tpm_available():
    """gun101tpm.tpm.check_tpm_available still works via backward compat shim."""
    from gun101tpm.tpm import check_tpm_available
    with patch('sys.platform', 'win32'):
        assert check_tpm_available() is False


def test_tpm_shim_seal_to_tpm():
    """gun101tpm.tpm.seal_to_tpm still works via backward compat shim."""
    from gun101tpm.tpm import seal_to_tpm
    with patch('sys.platform', 'win32'):
        with pytest.raises(RuntimeError, match="unavailable on Windows TBS"):
            seal_to_tpm(b"test", b"pass")


def test_tpm_shim_unseal_from_tpm():
    """gun101tpm.tpm.unseal_from_tpm still works via backward compat shim."""
    from gun101tpm.tpm import unseal_from_tpm
    with patch('sys.platform', 'darwin'):
        with pytest.raises(NotImplementedError):
            unseal_from_tpm(b"test", b"pass")
