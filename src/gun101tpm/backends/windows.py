"""
Windows TBS (TPM Base Services) backend for GUN-101-TPM.

Status: NOT YET IMPLEMENTED — stub only.
See ROADMAP.md for details.
"""

from .base import HardwareBackend


class WindowsTBSBackend(HardwareBackend):
    """Windows TPM backend using the TBS (TPM Base Services) API.

    This backend is not yet implemented.  All methods raise
    ``NotImplementedError`` with a clear message directing the user
    to the project roadmap.
    """

    _NOT_IMPLEMENTED_MSG = (
        "Windows TBS backend is not yet implemented. "
        "See ROADMAP.md for current status and planned support."
    )

    def check_available(self) -> bool:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)

    def get_fingerprint(self) -> str:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)

    def seal(self, secret: bytes, password_auth: bytes) -> bytes:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)

    def unseal(self, sealed_blob: bytes, password_auth: bytes) -> bytes:
        raise NotImplementedError(self._NOT_IMPLEMENTED_MSG)
