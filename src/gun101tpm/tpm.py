"""
Backward-compatibility shim for GUN-101-TPM TPM operations.

All actual implementation has moved to gun101tpm.backends.
This module re-exports the public API so that existing code
importing from gun101tpm.tpm continues to work unchanged.
"""

from .backends import (  # noqa: F401
    check_tpm_available,
    get_tpm_fingerprint,
    seal_to_tpm,
    unseal_from_tpm,
)
from .backends.linux import _check_platform_supported  # noqa: F401