"""
Backend registry for GUN-101-TPM.

Auto-selects the correct hardware backend based on sys.platform.
Provides module-level convenience functions that delegate to the
active backend, preserving the existing call-site API.
"""

import sys
from .base import HardwareBackend

_backend_instance = None


def get_backend() -> HardwareBackend:
    """Return the platform-appropriate hardware backend (singleton)."""
    global _backend_instance
    if _backend_instance is not None:
        return _backend_instance

    if sys.platform in {"linux", "linux2"}:
        from .linux import LinuxTPMBackend
        _backend_instance = LinuxTPMBackend()
    elif sys.platform == "win32":
        from .windows import WindowsTBSBackend
        _backend_instance = WindowsTBSBackend()
    elif sys.platform == "darwin":
        from .macos import MacOSSecureEnclaveBackend
        _backend_instance = MacOSSecureEnclaveBackend()
    else:
        raise RuntimeError(
            f"Unsupported platform: {sys.platform}. "
            "GUN-101-TPM supports Linux (TPM 2.0), Windows (TBS), "
            "and macOS (Secure Enclave). See README.md for details."
        )
    return _backend_instance


def reset_backend() -> None:
    """Reset the cached backend instance (used by tests)."""
    global _backend_instance
    _backend_instance = None


# ── Convenience functions ────────────────────────────────────────────
# These preserve the existing call-site API used by handler.py and
# cli.py so that only the import path changes, not the call syntax.

def check_tpm_available() -> bool:
    """Check if the hardware security module is available."""
    return get_backend().check_available()


def get_tpm_fingerprint() -> str:
    """Return a fingerprint string for the hardware security module."""
    return get_backend().get_fingerprint()


def seal_to_tpm(secret: bytes, password_auth: bytes) -> bytes:
    """Seal secret bytes to the hardware security module."""
    return get_backend().seal(secret, password_auth)


def unseal_from_tpm(sealed_blob: bytes, password_auth: bytes) -> bytes:
    """Unseal secret bytes from the hardware security module."""
    return get_backend().unseal(sealed_blob, password_auth)
