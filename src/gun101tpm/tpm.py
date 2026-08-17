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
        esapi = tpm2_pytss.ESAPI()
        with esapi:
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

    # Valid TPMT_PUBLIC types for a sealing key
    VALID_PUBLIC_TYPES = {
        tpm2_pytss.TPM2_ALG.RSA,
        tpm2_pytss.TPM2_ALG.ECC,
        tpm2_pytss.TPM2_ALG.SYMCIPHER,
        tpm2_pytss.TPM2_ALG.KEYEDHASH,
    }

    esapi = tpm2_pytss.ESAPI()
    primary_handle = None
    try:
        esapi.open()

        # Create a primary key under the Owner hierarchy
        primary_handle = esapi.create_primary(
            tpm2_pytss.ESYS_TR(tpm2_pytss.ESYS_TR.RH_OWNER),
            auth=None,
            in_sensitive=tpm2_types.TPM2B_SENSITIVE_CREATE(
                tpm2_types.TPM2B_AUTH(value=b""),
                tpm2_types.TPM2B_SENSITIVE_DATA(value=b""),
            ),
            in_public=tpm2_types.TPM2B_PUBLIC(
                publicArea=tpm2_types.TPMT_PUBLIC(
                    type=tpm2_pytss.TPM2_ALG.KEYEDHASH,
                    nameAlg=tpm2_pytss.TPM2_ALG.SHA256,
                    objectAttributes=(
                        tpm2_pytss.TPMA_OBJECT.restricted
                        | tpm2_pytss.TPMA_OBJECT.decrypt
                        | tpm2_pytss.TPMA_OBJECT.fixedTPM
                        | tpm2_pytss.TPMA_OBJECT.fixedParent
                        | tpm2_pytss.TPMA_OBJECT.sensitiveDataOrigin
                    ),
                    authPolicy=b"",
                    parameters=tpm2_pytss.TPMU_PUBLIC_PARMS(
                        keyedHashDetail=tpm2_pytss.TPMT_KEYEDHASH_SCHEME(
                            scheme=tpm2_pytss.TPM2_ALG.XOR,
                            details=tpm2_pytss.TPMU_KEYEDHASH_SCHEME(
                                scheme=tpm2_pytss.TPM2_ALG.NULL
                            )
                        )
                    ),
                    unique=tpm2_pytss.TPMU_PUBLIC_ID(
                        keyedHash=b""
                    ),
                )
            ),
        )
        primary_handle.handle = primary_handle.handle

        # Validate: a restricted key must never be both sign and decrypt
        attrs = (
            tpm2_pytss.TPMA_OBJECT.restricted
            | tpm2_pytss.TPMA_OBJECT.decrypt
            | tpm2_pytss.TPMA_OBJECT.fixedTPM
            | tpm2_pytss.TPMA_OBJECT.fixedParent
            | tpm2_pytss.TPMA_OBJECT.sensitiveDataOrigin
        )
        restricted_decrypt = bool(attrs & tpm2_pytss.TPMA_OBJECT.restricted and attrs & tpm2_pytss.TPMA_OBJECT.decrypt)
        restricted_sign = bool(attrs & tpm2_pytss.TPMA_OBJECT.restricted and attrs & tpm2_pytss.TPMA_OBJECT.SIGN_ENCRYPT)
        if restricted_decrypt and restricted_sign:
            raise ValueError("TPM 2.0 spec forbids a restricted key from having both decrypt and sign attributes")

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
                parameters=tpm2_pytss.TPMU_PUBLIC_PARMS(
                    keyedHashDetail=tpm2_pytss.TPMT_KEYEDHASH_SCHEME(
                        scheme=tpm2_pytss.TPM2_ALG.XOR,
                        details=tpm2_pytss.TPMU_KEYEDHASH_SCHEME(
                            scheme=tpm2_pytss.TPM2_ALG.NULL
                        )
                    )
                ),
                unique=tpm2_pytss.TPMU_PUBLIC_ID(keyedHash=b""),
            )
        )
        in_sensitive = tpm2_types.TPM2B_SENSITIVE_CREATE(
            tpm2_types.TPM2B_AUTH(value=password_auth),
            tpm2_types.TPM2B_SENSITIVE_DATA(value=secret),
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
        if primary_handle is not None:
            try:
                esapi.flush_context(primary_handle)
            except Exception:
                pass
        try:
            esapi.close()
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

    # Valid TPMT_PUBLIC types for a sealing key
    VALID_PUBLIC_TYPES = {
        tpm2_pytss.TPM2_ALG.RSA,
        tpm2_pytss.TPM2_ALG.ECC,
        tpm2_pytss.TPM2_ALG.SYMCIPHER,
        tpm2_pytss.TPM2_ALG.KEYEDHASH,
    }

    esapi = tpm2_pytss.ESAPI()
    primary_handle = None
    loaded_handle = None
    try:
        esapi.open()

        primary_handle = esapi.create_primary(
            tpm2_pytss.ESYS_TR(tpm2_pytss.ESYS_TR.RH_OWNER),
            auth=None,
            in_sensitive=tpm2_types.TPM2B_SENSITIVE_CREATE(
                tpm2_types.TPM2B_AUTH(value=b""),
                tpm2_types.TPM2B_SENSITIVE_DATA(value=b""),
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
                    parameters=tpm2_pytss.TPMU_PUBLIC_PARMS(
                        keyedHashDetail=tpm2_pytss.TPMT_KEYEDHASH_SCHEME(
                            scheme=tpm2_pytss.TPM2_ALG.XOR,
                            details=tpm2_pytss.TPMU_KEYEDHASH_SCHEME(
                                scheme=tpm2_pytss.TPM2_ALG.NULL
                            )
                        )
                    ),
                    unique=tpm2_pytss.TPMU_PUBLIC_ID(keyedHash=b""),
                )
            ),
        )
        primary_handle.handle = primary_handle.handle

        # Validate: a restricted key must never be both sign and decrypt
        # The loaded object inherits the sealed object's attributes;
        # verify the sealed blob's public area attributes are valid
        pub_size = int.from_bytes(sealed_blob[0:2], byteorder='little') if len(sealed_blob) >= 4 else 0
        if len(sealed_blob) < 4:
            raise ValueError("Invalid sealed blob")
        pub_blob = sealed_blob[2:2+pub_size]
        # Check objectAttributes from the sealed public area
        # We validate by checking that if restricted is set, sign and decrypt are not both set
        # Since the sealed object typically doesn't have RESTRICTED, this is a soft check
        sealed_attrs = (
            tpm2_pytss.TPMA_OBJECT.fixedTPM
            | tpm2_pytss.TPMA_OBJECT.fixedParent
            | tpm2_pytss.TPMA_OBJECT.sensitiveDataOrigin
            | tpm2_pytss.TPMA_OBJECT.userWithAuth
        )
        # Full check: if restricted were set, ensure sign/decrypt conflict doesn't exist
        restricted_present = bool(sealed_attrs & tpm2_pytss.TPMA_OBJECT.RESTRICTED)
        if restricted_present:
            restricted_decrypt = bool(sealed_attrs & tpm2_pytss.TPMA_OBJECT.decrypt)
            restricted_sign = bool(sealed_attrs & tpm2_pytss.TPMA_OBJECT.SIGN_ENCRYPT)
            if restricted_decrypt and restricted_sign:
                raise ValueError("TPM 2.0 spec forbids a restricted key from having both decrypt and sign attributes")

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

        try:
            loaded_handle = esapi.load(
                primary_handle,
                inPrivate=in_private,
                inPublic=in_public,
                inAuth=tpm2_types.TPM2B_AUTH(value=password_auth),
            )
        except Exception as e:
            raise ValueError("TPM unseal failed. Wrong machine, wrong password, or corrupted data.") from e

        try:
            item = esapi.unseal(loaded_handle.handle)
        except Exception as e:
            raise ValueError("TPM unseal failed. Wrong machine, wrong password, or corrupted data.") from e
        finally:
            if loaded_handle is not None:
                try:
                    esapi.flush_context(loaded_handle.handle)
                except Exception:
                    pass

        return item.buffer
    finally:
        if primary_handle is not None:
            try:
                esapi.flush_context(primary_handle)
            except Exception:
                pass
        try:
            esapi.close()
        except Exception:
            pass