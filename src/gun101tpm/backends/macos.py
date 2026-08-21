"""
macOS Secure Enclave backend for GUN-101-TPM.

Status: NOT YET IMPLEMENTED — stub only.
Most Mac hardware lacks a TPM 2.0 chip; this backend would use
the Secure Enclave as an alternative hardware root of trust.
See ROADMAP.md for details.
"""

from .base import HardwareBackend


class MacOSSecureEnclaveBackend(HardwareBackend):
    """macOS backend using the Secure Enclave.

    This backend is not yet implemented.  All methods raise
    ``NotImplementedError`` with a clear message directing the user
    to the project roadmap.
    """

    _NOT_IMPLEMENTED_MSG = (
        "macOS Secure Enclave backend is not yet implemented. "
        "Most Mac hardware lacks a TPM 2.0 chip; a Secure Enclave-based "
        "backend is planned. See ROADMAP.md for current status."
    )

    def check_available(self) -> bool:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)

    def get_fingerprint(self) -> str:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)

    def seal(self, secret: bytes, password_auth: bytes) -> bytes:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)

    def unseal(self, sealed_blob: bytes, password_auth: bytes) -> bytes:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)
