"""
TPM 2.0 operations for GUN-101-TPM.
"""

import hashlib
import logging
import sys

logger = logging.getLogger(__name__)


def _check_platform_supported():
    """Raise a clear error on unsupported platforms, before any
    tpm2_pytss import is attempted."""
    import sys
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
    """
    import tpm2_pytss
    from tpm2_pytss import types as tpm2_types
    from tpm2_pytss import TPM2_ALG

    # TPMT_KEYEDHASH_SCHEME: scheme + details
    kh_scheme = tpm2_types.TPMT_KEYEDHASH_SCHEME(
        scheme=TPM2_ALG.NULL,
        details=tpm2_types.TPMU_SCHEME_KEYEDHASH(
            exclusiveOr=tpm2_types.TPMS_SCHEME_XOR(
                hashAlg=TPM2_ALG.SHA256, kdf=TPM2_ALG.KDF1_SP800_108
            )
),
        )
    # TPMS_KEYEDHASH_PARMS: scheme + details (union)
    kh_parms = tpm2_types.TPMS_KEYEDHASH_PARMS(
        scheme=kh_scheme,
    )
    return kh_parms


def check_tpm_available() -> bool:
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


def get_tpm_fingerprint() -> str:
    """
    Return a SHA-256 fingerprint of the Endorsement Key (EK) public area.
    Returns a colon-separated uppercase hex string.
    """
    import tpm2_pytss

    with tpm2_pytss.ESAPI() as esapi:
        public = esapi.read_public(tpm2_pytss.ESYS_TR.ENDORSEMENT)
        marshalled = public.marshal()
        digest = hashlib.sha256(marshalled).hexdigest().upper()
        formatted = ':'.join([digest[i:i+2] for i in range(0, len(digest), 2)])
        return formatted


def seal_to_tpm(secret: bytes, password_auth: bytes) -> bytes:
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

        # Create a primary key under the Owner hierarchy.
        # Object attributes: restricted | decrypt | fixedTPM | fixedParent | sensitiveDataOrigin
        # A restricted key must never be both 'sign' and 'decrypt' at once
        # (TPM 2.0 spec forbids this combination). We only use decrypt.
        primary_handle = esapi.create_primary(
            in_sensitive=_make_tpm2b_sensitive_create(
                tpm2_types.TPM2B_AUTH(buffer=b""),
                tpm2_types.TPM2B_SENSITIVE_DATA(buffer=secret),
            ),
            in_public=tpm2_types.TPM2B_PUBLIC(
                publicArea=tpm2_types.TPMT_PUBLIC(
                    type=tpm2_pytss.TPM2_ALG.SYMCIPHER,
                    nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                    objectAttributes=(
                        tpm2_pytss.TPMA_OBJECT.RESTRICTED
                        | tpm2_pytss.TPMA_OBJECT.DECRYPT
                        | tpm2_pytss.TPMA_OBJECT.FIXEDTPM
                        | tpm2_pytss.TPMA_OBJECT.FIXEDPARENT
                        
                        | tpm2_pytss.TPMA_OBJECT.USERWITHAUTH
                    ),
                    authPolicy=b"",
                    parameters=tpm2_types.TPMU_PUBLIC_PARMS(
                        keyedHashDetail=_make_keyed_hash_public_params()
                    ),
                    unique=tpm2_types.TPMU_PUBLIC_ID(keyedHash=b""),
                )
            ),
        )
        # esapi.create_primary() returns a tuple: (ESYS_TR, TPM2B_PUBLIC, ...)
        primary_handle = primary_handle[0]

        # Create a sealed data object under the primary key.
        # Object attributes: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth
        # userWithAuth gates unseal behind the auth value (presented via tr_set_auth).
        in_public = tpm2_types.TPM2B_PUBLIC(
            publicArea=tpm2_types.TPMT_PUBLIC(
                type=tpm2_pytss.TPM2_ALG.SYMCIPHER,
                nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                objectAttributes=(
                    tpm2_pytss.TPMA_OBJECT.FIXEDTPM
                    | tpm2_pytss.TPMA_OBJECT.DECRYPT
                    | tpm2_pytss.TPMA_OBJECT.FIXEDPARENT
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
        in_sensitive = _make_tpm2b_sensitive_create(
            tpm2_types.TPM2B_AUTH(buffer=password_auth),
            tpm2_types.TPM2B_SENSITIVE_DATA(buffer=secret),
        )
        create_result = esapi.create(
            primary_handle,
            in_sensitive,
            in_public,
        )
        # esapi.create() returns a tuple: (ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION)
        outside_priv = create_result[1]
        outside_pub = create_result[2]
        esapi.flush_context(primary_handle)
        primary_handle = None  # Mark as flushed

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


def unseal_from_tpm(sealed_blob: bytes, password_auth: bytes) -> bytes:
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

        primary_handle = esapi.create_primary(
            in_sensitive=_make_tpm2b_sensitive_create(
                tpm2_types.TPM2B_AUTH(buffer=b""),
                tpm2_types.TPM2B_SENSITIVE_DATA(buffer=b""),
            ),
            in_public=tpm2_types.TPM2B_PUBLIC(
                publicArea=tpm2_types.TPMT_PUBLIC(
                    type=tpm2_pytss.TPM2_ALG.SYMCIPHER,
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
            ),
        )
        # esapi.create_primary() returns a tuple: (ESYS_TR, TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_DIGEST, TPMT_TK_CREATION)
        primary_handle = primary_handle[0]

        # Parse the sealed blob
        if len(sealed_blob) < 4:
            raise ValueError("Invalid sealed blob")
        pub_size = int.from_bytes(sealed_blob[0:2], byteorder='little')
        if 2 + pub_size > len(sealed_blob):
            raise ValueError("Invalid sealed blob")
        pub_blob = sealed_blob[2:2+pub_size]
        priv_blob = sealed_blob[2+pub_size:]

        in_public = tpm2_types.TPM2B_PUBLIC()
        in_public.buffer = pub_blob
        in_private = tpm2_types.TPM2B_PRIVATE()
        in_private.buffer = priv_blob

        # Load the sealed object into the TPM.
        # TPM2_Load does NOT take an inAuth parameter; tr_set_auth gates the unseal.
        loaded_handle = esapi.load(
            primary_handle,
            in_private,
            in_public,
        )

        # CRITICAL: Set the auth value on the loaded handle using tr_set_auth.
        # This is the real mechanism for presenting the password-derived auth value.
        # TPM2_Load does NOT take an inAuth parameter; tr_set_auth gates the unseal.
        # The password-derived KEK is presented as the TPM object's auth value,
        # so both the TPM AND the correct password are required to unseal.
        esapi.tr_set_auth(loaded_handle, tpm2_types.TPM2B_AUTH(buffer=password_auth))

        # Now unseal - this will use the auth value set above
        try:
            item = esapi.unseal(loaded_handle.handle)
        except Exception as e:
            raise ValueError("TPM unseal failed. Wrong machine, wrong password, or corrupted data.") from e

        return item.buffer
    finally:
        if loaded_handle is not None:
            try:
                esapi.flush_context(loaded_handle.handle)
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