"""
Linux TPM 2.0 backend for GUN-101-TPM.

Uses tpm2-pytss to communicate with the kernel TPM 2.0 device
(/dev/tpm0, /dev/tpmrm0).
"""

import hashlib
import logging
import sys

from .base import HardwareBackend

logger = logging.getLogger(__name__)


def _check_platform_supported():
    """Raise a clear error on unsupported platforms, before any
    tpm2_pytss import is attempted."""
    if sys.platform not in {"linux", "linux2", "Linux"}:
        raise RuntimeError(
            f"GUN-101-TPM is currently Linux-only (detected: {sys.platform}). "
            "TPM 2.0 hardware binding is not yet supported on this "
            "platform. See README.md for details and current roadmap."
        )


def _make_tpm2b_sensitive_create(auth, data):
    """
    Construct a TPM2B_SENSITIVE_CREATE with the given auth and data.

    TPM2B_SENSITIVE_CREATE only accepts _cdata positionally plus keyword args.
    We build it by creating the outer object and setting the inner sensitive fields.
    """
    import tpm2_pytss
    from tpm2_pytss import types as tpm2_types

    sens_create = tpm2_types.TPM2B_SENSITIVE_CREATE()
    sens_inner = sens_create.sensitive
    sens_inner.userAuth = auth
    sens_inner.data = data
    return sens_create


def _make_keyed_hash_public_params():
    """
    Build the TPMS_KEYEDHASH_PARMS structure for a KEYEDHASH public area.
    This is the correct type for the keyedHashDetail field of TPMU_PUBLIC_PARMS.

    Used only for the CHILD (sealed data) object, which must have scheme=NULL:
    XOR/HMAC schemes only apply to objects that actually exercise decrypt/sign
    capability, which a pure sealed-data object does not have.
    """
    import tpm2_pytss
    from tpm2_pytss import types as tpm2_types
    from tpm2_pytss import TPM2_ALG

    kh_scheme = tpm2_types.TPMT_KEYEDHASH_SCHEME(
        scheme=TPM2_ALG.NULL,
    )
    kh_parms = tpm2_types.TPMS_KEYEDHASH_PARMS(
        scheme=kh_scheme,
    )
    return kh_parms


def _make_primary_in_public(tpm2_pytss, tpm2_types):
    """
    Build the primary (parent) key's public template.

    Type SYMCIPHER (AES-128-CFB) with restricted+decrypt+sensitiveDataOrigin+
    userWithAuth. Only RSA/ECC/SYMCIPHER are valid TPM storage/wrapping
    parents -- a KEYEDHASH object cannot serve as a parent for Create/Load
    of child objects, even with restricted+decrypt set.

    IMPORTANT: This exact template (including empty in_sensitive data, since
    sensitiveDataOrigin means the TPM generates its own key material) must be
    used identically in both seal_to_tpm() and unseal_from_tpm() -- primary
    keys are deterministically regenerated from their template, and any
    mismatch derives a *different* key, which will fail the private blob's
    integrity check on load.
    """
    return tpm2_types.TPM2B_PUBLIC(
        publicArea=tpm2_types.TPMT_PUBLIC(
            type=tpm2_pytss.TPM2_ALG.SYMCIPHER,
            nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
            objectAttributes=(
                tpm2_pytss.TPMA_OBJECT.RESTRICTED
                | tpm2_pytss.TPMA_OBJECT.DECRYPT
                | tpm2_pytss.TPMA_OBJECT.FIXEDTPM
                | tpm2_pytss.TPMA_OBJECT.FIXEDPARENT
                | tpm2_pytss.TPMA_OBJECT.SENSITIVEDATAORIGIN
                | tpm2_pytss.TPMA_OBJECT.USERWITHAUTH
            ),
            authPolicy=b"",
            parameters=tpm2_types.TPMU_PUBLIC_PARMS(
                symDetail=tpm2_types.TPMS_SYMCIPHER_PARMS(
                    sym=tpm2_types.TPMT_SYM_DEF_OBJECT.parse('aes128cfb')
                ),
            ),
            unique=tpm2_types.TPMU_PUBLIC_ID(sym=b""),
        )
    )


class LinuxTPMBackend(HardwareBackend):
    """Linux TPM 2.0 backend using tpm2-pytss."""

    def check_available(self) -> bool:
        """
        Check if a TPM 2.0 device is available.
        Returns True if successful, False otherwise.
        Never raises an exception; returns False on any error.
        """
        _check_platform_supported()
        try:
            import tpm2_pytss
            with tpm2_pytss.ESAPI() as esapi:
                return True
        except Exception:
            return False

    def get_fingerprint(self) -> str:
        """
        Return a SHA-256 fingerprint of the standard RSA Endorsement Key (EK)
        public area.

        tpm2_pytss.ESYS_TR.ENDORSEMENT is a *hierarchy* handle, not an object
        handle -- read_public() cannot be called on it directly, since nothing
        is persisted/loaded there by default (real hardware sometimes has an EK
        pre-provisioned at a separate well-known persistent handle, but relying
        on that isn't portable). Instead we create the standard EK primary
        fresh under the Endorsement hierarchy each time: primary keys are
        deterministically regenerated from their template + hierarchy on a
        given TPM, so this reliably reproduces the exact same key -- and
        therefore the exact same fingerprint -- every time, without requiring
        any pre-provisioning.

        Returns a colon-separated uppercase hex string.
        """
        import tpm2_pytss

        with tpm2_pytss.ESAPI() as esapi:
            esapi.startup(tpm2_pytss.TPM2_SU.CLEAR)
            ek_handle = None
            try:
                ek = esapi.create_primary(
                    in_sensitive=None,
                    in_public='rsa2048',
                    primary_handle=tpm2_pytss.ESYS_TR.ENDORSEMENT,
                )
                ek_handle = ek[0]
                public, name, qualified_name = esapi.read_public(ek_handle)
                marshalled = public.marshal()
            finally:
                if ek_handle is not None:
                    try:
                        esapi.flush_context(ek_handle)
                    except Exception:
                        pass
            digest = hashlib.sha256(marshalled).hexdigest().upper()
            formatted = ':'.join([digest[i:i+2] for i in range(0, len(digest), 2)])
            return formatted

    def seal(self, secret: bytes, password_auth: bytes) -> bytes:
        """
        Seal the given secret bytes to the TPM.

        Returns the sealed blob (public + private parts) as bytes.
        Both the TPM and the correct password-derived auth value are required.
        """
        _check_platform_supported()
        import tpm2_pytss
        from tpm2_pytss import types as tpm2_types

        esapi = tpm2_pytss.ESAPI()
        primary_handle = None
        try:
            esapi.startup(tpm2_pytss.constants.TPM2_SU.CLEAR)

            # Create a primary (parent) key under the Owner hierarchy.
            # in_sensitive data is EMPTY: sensitiveDataOrigin means the TPM
            # generates its own key material for the primary. The actual secret
            # is sealed into the CHILD object below, not the primary.
            primary_handle = esapi.create_primary(
                in_sensitive=_make_tpm2b_sensitive_create(
                    tpm2_types.TPM2B_AUTH(buffer=b""),
                    tpm2_types.TPM2B_SENSITIVE_DATA(buffer=b""),
                ),
                in_public=_make_primary_in_public(tpm2_pytss, tpm2_types),
            )
            # esapi.create_primary() returns a tuple:
            # (ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION)
            primary_handle = primary_handle[0]

            # Create a sealed data object (the child) under the primary key.
            # Type KEYEDHASH with scheme=NULL and no restricted/decrypt/sign --
            # this is the only object shape TPM2_Unseal actually operates on.
            # Object attributes: fixedTPM | fixedParent | userWithAuth
            # userWithAuth gates unseal behind the auth value (via tr_set_auth).
            in_public = tpm2_types.TPM2B_PUBLIC(
                publicArea=tpm2_types.TPMT_PUBLIC(
                    type=tpm2_pytss.TPM2_ALG.KEYEDHASH,
                    nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                    objectAttributes=(
                        tpm2_pytss.TPMA_OBJECT.FIXEDTPM
                        | tpm2_pytss.TPMA_OBJECT.FIXEDPARENT
                        | tpm2_pytss.TPMA_OBJECT.USERWITHAUTH
                    ),
                    authPolicy=b"",
                    parameters=tpm2_types.TPMU_PUBLIC_PARMS(
                        keyedHashDetail=_make_keyed_hash_public_params()
                    ),
                    unique=tpm2_types.TPMU_PUBLIC_ID(keyedHash=b""),
                )
            )
            in_sensitive = _make_tpm2b_sensitive_create(
                tpm2_types.TPM2B_AUTH(buffer=password_auth),
                tpm2_types.TPM2B_SENSITIVE_DATA(buffer=secret),
            )
            create_result = esapi.create(
                primary_handle,
                in_sensitive,
                in_public,
            )
            # esapi.create() returns a tuple:
            # (TPM2B_PRIVATE, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION)
            outside_priv = create_result[0]
            outside_pub = create_result[1]
            esapi.flush_context(primary_handle)
            primary_handle = None  # Mark as flushed

            # Both marshal() outputs already include their own TPM2B wire-format
            # length prefix, so unseal_from_tpm can unmarshal() them back
            # sequentially without any manual length bookkeeping.
            sealed_blob = outside_pub.marshal() + outside_priv.marshal()
            return sealed_blob
        finally:
            try:
                esapi.shutdown()
            except Exception:
                pass
            # Clean up primary handle if still alive
            if primary_handle is not None:
                try:
                    esapi.flush_context(primary_handle)
                except Exception:
                    pass

    def unseal(self, sealed_blob: bytes, password_auth: bytes) -> bytes:
        """
        Unseal the given sealed blob (public+private) using the TPM.

        Returns the original secret bytes.
        On failure, raises ValueError with a message indicating possible wrong machine.
        Both the TPM and the correct password-derived auth value are required.
        """
        _check_platform_supported()
        import tpm2_pytss
        from tpm2_pytss import types as tpm2_types

        esapi = tpm2_pytss.ESAPI()
        primary_handle = None
        loaded_handle = None
        try:
            esapi.startup(tpm2_pytss.constants.TPM2_SU.CLEAR)

            # Must be byte-for-byte identical to the primary template in
            # seal_to_tpm() -- see _make_primary_in_public() docstring.
            primary_handle = esapi.create_primary(
                in_sensitive=_make_tpm2b_sensitive_create(
                    tpm2_types.TPM2B_AUTH(buffer=b""),
                    tpm2_types.TPM2B_SENSITIVE_DATA(buffer=b""),
                ),
                in_public=_make_primary_in_public(tpm2_pytss, tpm2_types),
            )
            # esapi.create_primary() returns a tuple:
            # (ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION)
            primary_handle = primary_handle[0]

            # Parse the sealed blob. seal_to_tpm() writes outside_pub.marshal() +
            # outside_priv.marshal() back-to-back; each marshal() output already
            # includes its own TPM2B wire-format length prefix, so we unmarshal
            # directly against the full blob rather than manually slicing lengths
            # (which was previously done incorrectly, and with the wrong
            # endianness -- TPM wire format is big-endian).
            try:
                in_public, pub_consumed = tpm2_types.TPM2B_PUBLIC.unmarshal(sealed_blob)
                in_private, _ = tpm2_types.TPM2B_PRIVATE.unmarshal(sealed_blob[pub_consumed:])
            except Exception as e:
                raise ValueError("Invalid sealed blob") from e

            # Load the sealed object into the TPM.
            # TPM2_Load does NOT take an inAuth parameter; tr_set_auth gates the unseal.
            loaded_handle = esapi.load(
                primary_handle,
                in_private,
                in_public,
            )

            # CRITICAL: Set the auth value on the loaded handle using tr_set_auth.
            # This is the real mechanism for presenting the password-derived auth value.
            # The password-derived KEK is presented as the TPM object's auth value,
            # so both the TPM AND the correct password are required to unseal.
            esapi.tr_set_auth(loaded_handle, tpm2_types.TPM2B_AUTH(buffer=password_auth))

            # Now unseal - this will use the auth value set above.
            # esapi.load() returns an ESYS_TR value directly (not an object with
            # a .handle attribute), so loaded_handle is used as-is everywhere below.
            try:
                item = esapi.unseal(loaded_handle)
            except Exception as e:
                raise ValueError("TPM unseal failed. Wrong machine, wrong password, or corrupted data.") from e

            return bytes(item.buffer)
        finally:
            if loaded_handle is not None:
                try:
                    esapi.flush_context(loaded_handle)
                except Exception:
                    pass
            if primary_handle is not None:
                try:
                    esapi.flush_context(primary_handle)
                except Exception:
                    pass
            try:
                esapi.shutdown()
            except Exception:
                pass
