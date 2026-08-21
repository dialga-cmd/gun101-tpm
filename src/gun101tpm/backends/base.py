"""
Abstract base class defining the hardware security backend interface.

Every platform backend (Linux TPM, Windows TBS, macOS Secure Enclave)
must implement this interface.
"""

from abc import ABC, abstractmethod


class HardwareBackend(ABC):
    """Contract for platform-specific hardware security backends."""

    @abstractmethod
    def check_available(self) -> bool:
        """Check whether the hardware security module is present and usable.

        Returns True if available, False otherwise.
        Should never raise an exception — returns False on any error.
        """

    @abstractmethod
    def get_fingerprint(self) -> str:
        """Return a human-readable fingerprint string for the hardware module.

        The fingerprint is used only for diagnostics (e.g. ``check-tpm``
        CLI command). It is NOT stored in encrypted containers.

        Returns a colon-separated uppercase hex string.
        """

    @abstractmethod
    def seal(self, secret: bytes, password_auth: bytes) -> bytes:
        """Seal the given secret bytes to the hardware module.

        Args:
            secret: The plaintext secret to seal.
            password_auth: Password-derived auth value (e.g. Argon2id KEK).

        Returns:
            Opaque sealed blob bytes.  The format is backend-specific.
        """

    @abstractmethod
    def unseal(self, sealed_blob: bytes, password_auth: bytes) -> bytes:
        """Unseal a previously sealed blob using the hardware module.

        Args:
            sealed_blob: Opaque blob returned by a prior ``seal()`` call.
            password_auth: Password-derived auth value used during sealing.

        Returns:
            The original plaintext secret bytes.

        Raises:
            ValueError: If unseal fails (wrong machine, wrong password,
                        corrupted data, etc.).
        """
