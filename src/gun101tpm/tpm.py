"""
TPM 2.0 operations for GUN-101-TPM.
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

def check_tpm_available() -> bool:
    """
    Check if a TPM 2.0 device is available.
    Returns True if successful, False otherwise.
    Never raises an exception; returns False on any error.
    """
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
    """
    import tpm2_pytss
    from tpm2_pytss import types as tpm2_types

    esapi = tpm2_pytss.ESAPI()
    primary_handle = None
    try:
        # Use context manager pattern (esapi.open()/close() don't exist;
        # ESAPI uses __enter__/__exit__ via 'with tpm2_pytss.ESAPI() as esapi:')
        # But since we need to manage handles manually, use startup/shutdown
        esapi.startup(tpm2_pytss.constants.TPM2_SU.CLEAR)

        # Create a primary key under the Owner hierarchy
        primary_handle = esapi.create_primary(
            in_sensitive=tpm2_types.TPM2B_SENSITIVE_CREATE(
                tpm2_types.TPM2B_AUTH(buffer=b""),
                tpm2_types.TPM2B_SENSITIVE_DATA(buffer=b""),
            ),
            in_public=tpm2_types.TPM2B_PUBLIC(
                publicArea=tpm2_types.TPMT_PUBLIC(
                    type=tpm2_pytss.TPM2_ALG.KEYEDHASH,
                    nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                    objectAttributes=(
                        tpm2_pytss.TPMA_OBJECT.restricted
                        | tpm2_pytss.TPMA_OBJECT.DECRYPT
                        | tpm2_pytss.TPMA_OBJECT.fixedTPM
                        | tpm2_pytss.TPMA_OBJECT.fixedParent
                        | tpm2_pytss.TPMA_OBJECT.sensitiveDataOrigin
                    ),
                    authPolicy=b"",
                    parameters=tpm2_types.TPMU_PUBLIC_PARMS(
                        keyedHashDetail=tpm2_types.TPMT_KEYEDHASH_SCHEME(
                            scheme=tpm2_pytss.TPM2_ALG.XOR,
                            details=tpm2_types.TPMU_KEYEDHASH_SCHEME(
                                scheme=tpm2_pytss.TPM2_ALG.NULL
                            )
                        )
                    ),
                    unique=tpm2_types.TPMU_PUBLIC_ID(keyedHash=b""),
                )
            ),
        )
        primary_handle.handle = primary_handle.handle

        # Create a sealed data object under the primary key
        in_public = tpm2_types.TPM2B_PUBLIC(
            publicArea=tpm2_types.TPMT_PUBLIC(
                type=tpm2_pytss.TPM2_ALG.KEYEDHASH,
                nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                objectAttributes=(
                    tpm2_pytss.TPMA_OBJECT.fixedTPM
                    | tpm2_pytss.TPMA_OBJECT.fixedParent
                    | tpm2_pytss.TPMA_OBJECT.sensitiveDataOrigin
                    | tpm2_pytss.TPMA_OBJECT.userWithAuth
                ),
                authPolicy=b"",
                parameters=tpm2_types.TPMU_PUBLIC_PARMS(
                    keyedHashDetail=tpm2_types.TPMT_KEYEDHASH_SCHEME(
                        scheme=tpm2_pytss.TPM2_ALG.XOR,
                        details=tpm2_types.TPMU_KEYEDHASH_SCHEME(
                            scheme=tpm2_pytss.TPM2_ALG.NULL
                        )
                    )
                ),
                unique=tpm2_types.TPMU_PUBLIC_ID(keyedHash=b""),
            )
        )
        in_sensitive = tpm2_types.TPM2B_SENSITIVE_CREATE(
            tpm2_types.TPM2B_AUTH(buffer=password_auth),
            tpm2_types.TPM2B_SENSITIVE_DATA(buffer=secret),
        )
        create_result = esapi.create(
            primary_handle,
            inSensitive=in_sensitive,
            inPublic=in_public,
        )
        outside_priv = create_result.outPrivate
        outside_pub = create_result.outPublic
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
    """
    import tpm2_pytss
    from tpm2_pytss import types as tpm2_types

    esapi = tpm2_pytss.ESAPI()
    primary_handle = None
    loaded_handle = None
    try:
        esapi.startup(tpm2_pytss.constants.TPM2_SU.CLEAR)

        primary_handle = esapi.create_primary(
            in_sensitive=tpm2_types.TPM2B_SENSITIVE_CREATE(
                tpm2_types.TPM2B_AUTH(buffer=b""),
                tpm2_types.TPM2B_SENSITIVE_DATA(buffer=b""),
            ),
            in_public=tpm2_types.TPM2B_PUBLIC(
                publicArea=tpm2_types.TPMT_PUBLIC(
                    type=tpm2_pytss.TPM2_ALG.KEYEDHASH,
                    nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                    objectAttributes=(
                        tpm2_pytss.TPMA_OBJECT.fixedTPM
                        | tpm2_pytss.TPMA_OBJECT.fixedParent
                        | tpm2_pytss.TPMA_OBJECT.sensitiveDataOrigin
                        | tpm2_pytss.TPMA_OBJECT.userWithAuth
                    ),
                    authPolicy=b"",
                    parameters=tpm2_types.TPMU_PUBLIC_PARMS(
                        keyedHashDetail=tpm2_types.TPMT_KEYEDHASH_SCHEME(
                            scheme=tpm2_pytss.TPM2_ALG.XOR,
                            details=tpm2_types.TPMU_KEYEDHASH_SCHEME(
                                scheme=tpm2_pytss.TPM2_ALG.NULL
                            )
                        )
                    ),
                    unique=tpm2_types.TPMU_PUBLIC_ID(keyedHash=b""),
                )
            ),
        )
        primary_handle.handle = primary_handle.handle

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

        # Load the sealed object into the TPM
        loaded_handle = esapi.load(
            primary_handle,
            inPrivate=in_private,
            inPublic=in_public,
        )

        # CRITICAL: Set the auth value on the loaded handle using tr_set_auth
        # This is the real mechanism for presenting the password-derived auth value
        # TPM2_Load does NOT take an inAuth parameter; tr_set_auth gates the unseal
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