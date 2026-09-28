# Copyright (c) 2026 GUN-101-TPM contributors
# SPDX-License-Identifier: MIT

"""Portable unit tests for cryptography, handlers, and the CLI."""

import base64
import errno
import json
import sys

import pytest

from gun101tpm import cipher, cli, handler, kdf


def test_cipher_roundtrip_and_validation():
    key = b"k" * 32
    nonce, ciphertext, tag = cipher.encrypt(b"payload", key)

    assert cipher.decrypt(nonce, ciphertext, tag, key) == b"payload"
    nonce, ciphertext, tag = cipher.encrypt(
        b"payload", key, "CHACHA20-POLY1305"
    )
    assert cipher.decrypt(
        nonce, ciphertext, tag, key, "CHACHA20-POLY1305"
    ) == b"payload"
    with pytest.raises(ValueError, match="Key must be 32 bytes"):
        cipher.encrypt(b"payload", b"short")
    with pytest.raises(ValueError, match="Unsupported cipher"):
        cipher.encrypt(b"payload", key, "unknown")
    with pytest.raises(ValueError, match="Unsupported cipher"):
        cipher.decrypt(nonce, ciphertext, tag, key, "unknown")
    with pytest.raises(ValueError, match="Nonce"):
        cipher.decrypt(b"short", ciphertext, tag, key)
    with pytest.raises(ValueError, match="Tag"):
        cipher.decrypt(nonce, ciphertext, b"short", key)
    with pytest.raises(ValueError, match="Decryption failed"):
        cipher.decrypt(nonce, ciphertext[:-1] + b"x", tag, key)


def test_kdf_derivation_and_verification():
    salt = b"s" * 16
    derived = kdf.derive_key("password", salt)

    assert len(derived) == 32
    assert kdf.verify_key("password", salt, derived)
    assert not kdf.verify_key("wrong", salt, derived)
    with pytest.raises(ValueError, match="exactly 16 bytes"):
        kdf.derive_key("password", b"short")


def test_handler_roundtrip_with_fake_backend(monkeypatch):
    class FakeBackend:
        def seal(self, secret, password_auth):
            return b"sealed:" + secret + password_auth[:4]

    fake_backend = FakeBackend()
    monkeypatch.setattr(handler, "get_backend", lambda: fake_backend)
    captured = {}

    def fake_unseal(sealed_blob, password_auth):
        captured["blob"] = sealed_blob
        captured["auth"] = password_auth
        return captured["dek"]

    monkeypatch.setattr(handler, "unseal_from_tpm", fake_unseal)
    encrypted = handler.encrypt_file(b"secret", "password")
    container = json.loads(encrypted)
    captured["dek"] = b"k" * 32

    # The fake backend sealed the generated DEK; use the DEK recovered by the
    # fake unseal function to exercise the complete container path.
    original_seal = fake_backend.seal

    def seal_and_capture(secret, password_auth):
        captured["dek"] = secret
        return original_seal(secret, password_auth)

    fake_backend.seal = seal_and_capture
    encrypted = handler.encrypt_file(b"secret", "password")
    assert container["protocol"] == "GUN-101-TPM"
    assert handler.decrypt_file(encrypted, "password") == b"secret"
    assert captured["blob"].startswith(b"sealed:")


def test_handler_rejects_invalid_containers(monkeypatch):
    monkeypatch.setattr(handler, "unseal_from_tpm", lambda *_: b"k" * 32)

    with pytest.raises(ValueError, match="Invalid container format"):
        handler.decrypt_file(b"not-json", "password")
    with pytest.raises(ValueError, match="Unsupported protocol"):
        handler.decrypt_file(
            json.dumps({"protocol": "wrong", "version": "2.0"}).encode(),
            "password",
        )
    with pytest.raises(ValueError, match="Encrypted data must be bytes"):
        handler.decrypt_file("not-bytes", "password")
    with pytest.raises(ValueError, match="Failed to decode"):
        handler.decrypt_file(
            json.dumps({
                "protocol": "GUN-101-TPM",
                "version": "2.0",
                "salt": "%%%",
                "sealed_blob": "c2VhbGVk",
                "file_nonce": "bm9uY2U=",
                "file_tag": "dGFn",
                "ciphertext": "Y2lwaGVydGV4dA==",
            }).encode(),
            "password",
        )


def test_cli_encrypt_and_decrypt(tmp_path, monkeypatch):
    source = tmp_path / "input.txt"
    encrypted = tmp_path / "output.gun101"
    recovered = tmp_path / "recovered.txt"
    source.write_bytes(b"input")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    monkeypatch.setattr(cli, "encrypt_file", lambda data, password: b"sealed")
    monkeypatch.setattr(cli, "decrypt_file", lambda data, password: b"recovered")

    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(encrypted)]
    )
    cli.main()
    assert encrypted.read_bytes() == b"sealed"

    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(encrypted), "-o", str(recovered)]
    )
    cli.main()
    assert recovered.read_bytes() == b"recovered"


def test_cli_missing_input_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(tmp_path / "missing")])

    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1


def test_cli_check_tpm_and_help(monkeypatch):
    monkeypatch.setattr(cli, "check_tpm_available", lambda: True)
    monkeypatch.setattr(cli, "get_tpm_fingerprint", lambda: "AA:BB")
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "check-tpm"])
    cli.main()

    monkeypatch.setattr(cli, "check_tpm_available", lambda: False)
    cli.main()
    monkeypatch.setattr(sys, "argv", ["gun101tpm"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1


def test_cli_default_outputs_and_overwrite_refusal(tmp_path, monkeypatch):
    source = tmp_path / "input.txt"
    source.write_bytes(b"input")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    monkeypatch.setattr(cli, "encrypt_file", lambda data, password: b"sealed")
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source)]
    )
    cli.main()
    encrypted = tmp_path / "input.txt.gun101"
    assert encrypted.read_bytes() == b"sealed"

    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1

    monkeypatch.setattr(cli, "decrypt_file", lambda data, password: b"recovered")
    monkeypatch.setattr("builtins.input", lambda _: "y")
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(encrypted)]
    )
    cli.main()
    assert source.read_bytes() == b"recovered"


def test_cli_password_prompt_and_tpm_errors(monkeypatch):
    monkeypatch.delenv("GUN101TPM_PASSWORD", raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "prompted")
    assert cli.get_password() == "prompted"

    monkeypatch.setattr(cli, "check_tpm_available", lambda: True)
    monkeypatch.setattr(cli, "get_tpm_fingerprint", lambda: (_ for _ in ()).throw(RuntimeError("fingerprint")))
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "check-tpm"])
    with pytest.raises(SystemExit):
        cli.main()

    monkeypatch.setattr(cli, "check_tpm_available", lambda: (_ for _ in ()).throw(RuntimeError("TPM")))
    with pytest.raises(SystemExit):
        cli.main()


def test_cli_io_and_operation_errors(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    source.write_bytes(b"input")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    real_open = open

    def fail_read(path, mode="r", *args, **kwargs):
        if "r" in mode:
            raise OSError("read failure")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_read)
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit):
        cli.main()

    monkeypatch.setattr(cli, "encrypt_file", lambda *_: b"sealed")

    def fail_write(path, mode="r", *args, **kwargs):
        if "w" in mode:
            raise OSError("write failure")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_write)
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit):
        cli.main()

    monkeypatch.setattr("builtins.open", real_open)
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(tmp_path / "missing")])
    with pytest.raises(SystemExit):
        cli.main()

    monkeypatch.setattr(cli, "decrypt_file", lambda *_: b"recovered")
    non_suffix = tmp_path / "encrypted.bin"
    non_suffix.write_bytes(b"sealed")
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(non_suffix)])
    cli.main()
    assert (tmp_path / "encrypted.bin.decrypted").read_bytes() == b"recovered"

    monkeypatch.setattr("builtins.open", fail_read)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    with pytest.raises(SystemExit):
        cli.main()
    monkeypatch.setattr("builtins.open", real_open)

    monkeypatch.setattr(cli, "decrypt_file", lambda *_: (_ for _ in ()).throw(ValueError("decrypt")))
    with pytest.raises(SystemExit):
        cli.main()

    monkeypatch.setattr("builtins.open", fail_write)
    monkeypatch.setattr(cli, "decrypt_file", lambda *_: b"recovered")
    with pytest.raises(SystemExit):
        cli.main()

    monkeypatch.setattr("builtins.open", real_open)
    monkeypatch.setattr(cli, "encrypt_file", lambda *_: (_ for _ in ()).throw(ValueError("encrypt")))
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit):
        cli.main()


def test_handler_validation_and_cleanup(monkeypatch):
    class FakeBackend:
        def seal(self, secret, password_auth):
            return b"sealed"

    monkeypatch.setattr(handler, "get_backend", lambda: FakeBackend())
    with pytest.raises(ValueError, match="File data"):
        handler.encrypt_file("text", "password")
    with pytest.raises(ValueError, match="Password"):
        handler.encrypt_file(b"data", "")
    with pytest.raises(ValueError, match="Unsupported cipher"):
        handler.encrypt_file(b"data", "password", "unknown")
    monkeypatch.setattr(handler, "_clear_memory", lambda data: None)
    with pytest.raises(ValueError, match="File too large"):
        handler.encrypt_file(b"x" * ((1 << 30) + 1), "password")
    assert handler._clear_memory(b"bytes") is None
    assert handler._clear_memory(bytearray(b"bytes")) is None


def test_handler_unseal_and_cipher_failures(monkeypatch):
    container = {
        "protocol": "GUN-101-TPM",
        "version": "2.0",
        "salt": base64.b64encode(b"s" * 16).decode(),
        "sealed_blob": "c2VhbGVk",
        "file_nonce": "bm9uY2U=",
        "file_tag": "dGFn",
        "ciphertext": "Y2lwaGVy",
    }
    monkeypatch.setattr(handler, "unseal_from_tpm", lambda *_: (_ for _ in ()).throw(ValueError("unseal")))
    with pytest.raises(ValueError, match="TPM unseal failed"):
        handler.decrypt_file(json.dumps(container).encode(), "password")

    monkeypatch.setattr(handler, "unseal_from_tpm", lambda *_: b"k" * 32)
    monkeypatch.setattr(handler, "aes_decrypt", lambda *_: (_ for _ in ()).throw(ValueError("cipher")))
    with pytest.raises(ValueError, match="Decryption failed"):
        handler.decrypt_file(json.dumps(container).encode(), "password")


def test_handler_rejects_protocol_fields(monkeypatch):
    base = {
        "protocol": "GUN-101-TPM",
        "version": "2.0",
        "salt": base64.b64encode(b"s" * 16).decode(),
        "sealed_blob": "c2VhbGVk",
        "file_nonce": "bm9uY2U=",
        "file_tag": "dGFn",
        "ciphertext": "Y2lwaGVy",
    }
    for field, value, message in (
        ("version", "1.0", "Unsupported version"),
        ("cipher", "unknown", "Unsupported cipher"),
        ("sealed_blob", 42, "Failed to decode"),
        ("sealed_blob", "", "Failed to decode"),
    ):
        candidate = dict(base)
        candidate[field] = value
        with pytest.raises(ValueError, match=message):
            handler.decrypt_file(json.dumps(candidate).encode(), "password")

    with pytest.raises(ValueError, match="Invalid container format"):
        handler.decrypt_file(json.dumps([]).encode(), "password")


def test_kdf_verification_handles_invalid_input():
    assert not kdf.verify_key("password", b"bad", b"expected")


def test_kdf_retries_when_first_result_has_wrong_length(monkeypatch):
    class FakeHasher:
        calls = 0

        def __init__(self, **_kwargs):
            pass

        def hash(self, _password, salt):
            FakeHasher.calls += 1
            if FakeHasher.calls == 1:
                return "$argon2id$v=19$invalid$eA=="
            encoded = base64.b64encode(b"k" * 32).decode()
            return f"$argon2id$v=19$valid${encoded}"

    monkeypatch.setattr(kdf.argon2, "PasswordHasher", FakeHasher)

    assert kdf.derive_key("password", b"s" * 16) == b"k" * 32
    assert FakeHasher.calls == 2


def test_handler_clear_memory_implementation():
    ba = bytearray(b"sensitive_secret_data")
    handler._clear_memory(ba)
    assert all(b == 0 for b in ba)
    assert handler._clear_memory(b"immutable_bytes") is None
    assert handler._clear_memory(None) is None


def test_handler_encrypt_backend_modes(monkeypatch):
    class LinuxMockBackend:
        def seal(self, secret, auth):
            return b"linux_sealed"

    monkeypatch.setattr(handler, "get_backend", lambda: LinuxMockBackend())
    linux_enc = handler.encrypt_file(b"data", "password")
    linux_container = json.loads(linux_enc)
    assert linux_container["mode"] == "TPM"

    # NOTE: deliberately no Windows case here. WindowsTBSBackend.seal() is a
    # software stub that stores the DEK in the blob in plaintext, so asserting
    # mode == "TPM" for it would lock in a container that falsely advertises
    # hardware binding. Cover the Windows path once it is genuinely TPM-backed.


def test_handler_empty_and_invalid_data_inputs(monkeypatch):
    # API input validation for encrypt_file
    with pytest.raises(ValueError, match="File data must be bytes"):
        handler.encrypt_file(None, "password")  # type: ignore
    with pytest.raises(ValueError, match="File data must be bytes"):
        handler.encrypt_file(12345, "password")  # type: ignore
    with pytest.raises(ValueError, match="Password must be a non-empty string"):
        handler.encrypt_file(b"data", "")
    with pytest.raises(ValueError, match="Password must be a non-empty string"):
        handler.encrypt_file(b"data", None)  # type: ignore

    # API input validation for decrypt_file
    with pytest.raises(ValueError, match="Encrypted data must be bytes"):
        handler.decrypt_file(None, "password")  # type: ignore
    with pytest.raises(ValueError, match="Encrypted data must be bytes"):
        handler.decrypt_file(12345, "password")  # type: ignore
    with pytest.raises(ValueError, match="Password must be a non-empty string"):
        handler.decrypt_file(b"{}", "")
    with pytest.raises(ValueError, match="Password must be a non-empty string"):
        handler.decrypt_file(b"{}", None)  # type: ignore
    with pytest.raises(ValueError, match="Invalid container format"):
        handler.decrypt_file(b"", "password")

    # Empty data roundtrip through handler
    captured = {}

    class FakeBackend:
        def seal(self, secret, password_auth):
            captured["dek"] = secret
            return b"sealed:" + secret

    monkeypatch.setattr(handler, "get_backend", lambda: FakeBackend())
    monkeypatch.setattr(handler, "unseal_from_tpm", lambda blob, auth: captured["dek"])

    empty_encrypted = handler.encrypt_file(b"", "password")
    assert handler.decrypt_file(empty_encrypted, "password") == b""


def test_handler_corrupted_containers_and_truncation():
    # Truncated or malformed JSON
    truncated_payloads = [
        b"",
        b"{",
        b'{"protocol":',
        b'{"protocol": "GUN-101-TPM"',
        b'{"protocol": "GUN-101-TPM", "version": "2.0"',
        b'{"protocol": "GUN-101-TPM", "version": "2.0", "ciphertext": "abc',
        b"\x00\xff\xfe\xfd\x80\x90",
        b"not-even-close-to-json",
        b"null",
        b"true",
        b"12345",
        b'"just a string"',
    ]
    for payload in truncated_payloads:
        with pytest.raises(ValueError, match="Invalid container format"):
            handler.decrypt_file(payload, "password")


def test_handler_missing_and_invalid_field_types():
    base = {
        "protocol": "GUN-101-TPM",
        "version": "2.0",
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(b"s" * 16).decode(),
        "sealed_blob": base64.b64encode(b"sealed").decode(),
        "file_nonce": base64.b64encode(b"n" * 12).decode(),
        "file_tag": base64.b64encode(b"t" * 16).decode(),
        "ciphertext": base64.b64encode(b"ciphertext").decode(),
    }

    # Missing fields
    for missing in ("protocol", "version"):
        candidate = dict(base)
        del candidate[missing]
        with pytest.raises(ValueError, match=f"Unsupported {missing}"):
            handler.decrypt_file(json.dumps(candidate).encode(), "password")

    for missing in ("salt", "sealed_blob", "file_nonce", "file_tag", "ciphertext"):
        candidate = dict(base)
        del candidate[missing]
        with pytest.raises(ValueError, match="Failed to decode container fields"):
            handler.decrypt_file(json.dumps(candidate).encode(), "password")

    # Invalid non-string types for base64 fields
    for field in ("salt", "sealed_blob", "file_nonce", "file_tag", "ciphertext"):
        for invalid_val in (12345, None, True, ["a"], {"k": "v"}):
            candidate = dict(base)
            candidate[field] = invalid_val
            with pytest.raises(ValueError, match="Failed to decode container fields"):
                handler.decrypt_file(json.dumps(candidate).encode(), "password")

    # Invalid base64 encodings (bad characters, padding)
    for field in ("salt", "sealed_blob", "file_nonce", "file_tag", "ciphertext"):
        for bad_b64 in ("???not-base64???", "!@#$%", "abc"):
            candidate = dict(base)
            candidate[field] = bad_b64
            with pytest.raises(ValueError, match="Failed to decode container fields"):
                handler.decrypt_file(json.dumps(candidate).encode(), "password")


def test_handler_cryptographic_field_tampering(monkeypatch):
    captured = {}

    class FakeBackend:
        def seal(self, secret, auth):
            captured["dek"] = secret
            return b"sealed_blob_content"

    monkeypatch.setattr(handler, "get_backend", lambda: FakeBackend())
    monkeypatch.setattr(handler, "unseal_from_tpm", lambda blob, auth: captured["dek"])

    encrypted = handler.encrypt_file(b"test secret data", "password")
    container = json.loads(encrypted)

    # Tampered salt length (15 bytes instead of 16)
    c_salt = dict(container)
    c_salt["salt"] = base64.b64encode(b"s" * 15).decode()
    with pytest.raises(ValueError, match="Salt must be exactly 16 bytes"):
        handler.decrypt_file(json.dumps(c_salt).encode(), "password")

    # Tampered nonce length (11 bytes instead of 12)
    c_nonce = dict(container)
    c_nonce["file_nonce"] = base64.b64encode(b"n" * 11).decode()
    with pytest.raises(ValueError, match="Decryption failed. Data may be corrupted."):
        handler.decrypt_file(json.dumps(c_nonce).encode(), "password")

    # Tampered tag length (15 bytes instead of 16)
    c_tag = dict(container)
    c_tag["file_tag"] = base64.b64encode(b"t" * 15).decode()
    with pytest.raises(ValueError, match="Decryption failed. Data may be corrupted."):
        handler.decrypt_file(json.dumps(c_tag).encode(), "password")

    # Tampered ciphertext byte (cryptographic tag verification failure)
    c_ct = dict(container)
    raw_ct = base64.b64decode(c_ct["ciphertext"])
    tampered_ct = bytes([raw_ct[0] ^ 0x01]) + raw_ct[1:]
    c_ct["ciphertext"] = base64.b64encode(tampered_ct).decode()
    with pytest.raises(ValueError, match="Decryption failed. Data may be corrupted."):
        handler.decrypt_file(json.dumps(c_ct).encode(), "password")

    # Tampered tag byte
    c_tb = dict(container)
    raw_tb = base64.b64decode(c_tb["file_tag"])
    tampered_tb = bytes([raw_tb[0] ^ 0xFF]) + raw_tb[1:]
    c_tb["file_tag"] = base64.b64encode(tampered_tb).decode()
    with pytest.raises(ValueError, match="Decryption failed. Data may be corrupted."):
        handler.decrypt_file(json.dumps(c_tb).encode(), "password")

    # Unseal failure (wrong password / wrong machine / corrupted sealed_blob)
    monkeypatch.setattr(
        handler,
        "unseal_from_tpm",
        lambda *_: (_ for _ in ()).throw(ValueError("TPM unseal error")),
    )
    with pytest.raises(
        ValueError, match="TPM unseal failed. Wrong machine, wrong password, or corrupted data."
    ):
        handler.decrypt_file(encrypted, "password")


def test_handler_error_messages_do_not_leak_secrets(monkeypatch):
    secret_data = b"CONFIDENTIAL_PAYLOAD_ABC_123"
    secret_password = "ULTRA_SECRET_PASSWORD_XYZ_789"

    captured = {}

    class FakeBackend:
        def seal(self, secret, auth):
            captured["dek"] = secret
            return b"sealed"

    monkeypatch.setattr(handler, "get_backend", lambda: FakeBackend())
    monkeypatch.setattr(handler, "unseal_from_tpm", lambda b, a: captured.get("dek", b"k" * 32))

    encrypted = handler.encrypt_file(secret_data, secret_password)

    def assert_no_leak(err: Exception):
        err_str = str(err).lower()
        assert "confidential_payload" not in err_str
        assert "ultra_secret" not in err_str
        assert "xyz_789" not in err_str
        assert "abc_123" not in err_str

    with pytest.raises(ValueError) as exc:
        handler.decrypt_file(b"", secret_password)
    assert_no_leak(exc.value)

    with pytest.raises(ValueError) as exc:
        handler.decrypt_file(b"invalid-json", secret_password)
    assert_no_leak(exc.value)

    monkeypatch.setattr(
        handler,
        "unseal_from_tpm",
        lambda *_: (_ for _ in ()).throw(ValueError("unseal failed")),
    )
    with pytest.raises(ValueError) as exc:
        handler.decrypt_file(encrypted, secret_password)
    assert_no_leak(exc.value)

    monkeypatch.setattr(handler, "unseal_from_tpm", lambda b, a: b"wrong_key_for_aes_decrypt_32b!")
    with pytest.raises(ValueError) as exc:
        handler.decrypt_file(encrypted, secret_password)
    assert_no_leak(exc.value)


def test_cli_missing_and_directory_inputs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")

    # Missing file on encrypt
    missing_file = tmp_path / "nonexistent.txt"
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(missing_file)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert f"Error: File '{missing_file}' not found." in out

    # Missing file on decrypt
    missing_enc = tmp_path / "nonexistent.gun101"
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(missing_enc)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert f"Error: File '{missing_enc}' not found." in out

    # Directory passed as input on encrypt
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(sub_dir)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert f"Error: File '{sub_dir}' not found." in out

    # Directory passed as input on decrypt
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(sub_dir)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert f"Error: File '{sub_dir}' not found." in out


def test_cli_unreadable_input_permission_and_io_errors(tmp_path, monkeypatch, capsys):
    source = tmp_path / "input.txt"
    source.write_bytes(b"content")
    enc_source = tmp_path / "input.gun101"
    enc_source.write_bytes(b"content")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    real_open = open

    # PermissionError (EACCES) on encrypt read
    def fail_permission(path, mode="r", *args, **kwargs):
        if "r" in mode:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_permission)
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error reading file:" in out
    assert "Permission denied" in out

    # PermissionError on decrypt read
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(enc_source)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error reading file:" in out
    assert "Permission denied" in out

    # EIO on encrypt read
    def fail_io(path, mode="r", *args, **kwargs):
        if "r" in mode:
            raise OSError(errno.EIO, "Input/output error")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_io)
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error reading file:" in out
    assert "Input/output error" in out

    # EIO on decrypt read
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(enc_source)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error reading file:" in out
    assert "Input/output error" in out


def test_cli_empty_input_file_handling(tmp_path, monkeypatch, capsys):
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")
    output_enc = tmp_path / "empty.gun101"
    output_dec = tmp_path / "empty_decrypted.txt"
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")

    monkeypatch.setattr(cli, "encrypt_file", lambda data, pwd: b'{"protocol":"GUN-101-TPM","version":"2.0","data":""}')
    monkeypatch.setattr(cli, "decrypt_file", lambda data, pwd: b"")

    # Encrypting empty file succeeds
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(output_enc)]
    )
    cli.main()
    out, _ = capsys.readouterr()
    assert f"File encrypted successfully: {output_enc}" in out
    assert output_enc.exists()

    # Decrypting recovered empty file succeeds
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(output_enc), "-o", str(output_dec)]
    )
    cli.main()
    out, _ = capsys.readouterr()
    assert f"File decrypted successfully: {output_dec}" in out
    assert output_dec.read_bytes() == b""

    # Decrypting an empty (0 bytes) container file directly fails with clear error
    empty_container = tmp_path / "zero_bytes.gun101"
    empty_container.write_bytes(b"")
    monkeypatch.undo()  # restore real decrypt_file
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(empty_container)]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error during decryption: Invalid container format" in out


def test_cli_malformed_container_handling(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")

    # Truncated container
    trunc = tmp_path / "truncated.gun101"
    trunc.write_bytes(b'{"protocol": "GUN-101-TPM", "version": "2')
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(trunc)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error during decryption: Invalid container format" in out

    # Non-JSON garbage
    garbage = tmp_path / "garbage.gun101"
    garbage.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00")
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(garbage)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error during decryption: Invalid container format" in out

    # Missing protocol
    no_proto = tmp_path / "no_proto.gun101"
    no_proto.write_bytes(json.dumps({"version": "2.0"}).encode())
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(no_proto)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error during decryption: Unsupported protocol: None" in out

    # Tampered ciphertext
    monkeypatch.setattr(
        cli,
        "decrypt_file",
        lambda *_: (_ for _ in ()).throw(ValueError("Decryption failed. Data may be corrupted.")),
    )
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(garbage)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error during decryption: Decryption failed. Data may be corrupted." in out

    # Unseal failure
    monkeypatch.setattr(
        cli,
        "decrypt_file",
        lambda *_: (_ for _ in ()).throw(
            ValueError("TPM unseal failed. Wrong machine, wrong password, or corrupted data.")
        ),
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error during decryption: TPM unseal failed. Wrong machine, wrong password, or corrupted data." in out


def test_cli_unwritable_output_paths(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source.txt"
    source.write_bytes(b"valid content")
    enc_file = tmp_path / "source.gun101"
    enc_file.write_bytes(b"encrypted content")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    monkeypatch.setattr(cli, "encrypt_file", lambda *_: b"sealed_data")
    monkeypatch.setattr(cli, "decrypt_file", lambda *_: b"plain_data")

    # 1. Output directory does not exist
    bad_dir = tmp_path / "nonexistent_dir" / "out.gun101"
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(bad_dir)]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "File encrypted successfully" not in out

    bad_dec_dir = tmp_path / "nonexistent_dir" / "out.txt"
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(enc_file), "-o", str(bad_dec_dir)]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "File decrypted successfully" not in out

    # 2. Output path is an existing directory
    existing_dir = tmp_path / "dir_target"
    existing_dir.mkdir()
    monkeypatch.setattr("builtins.input", lambda _: "y")
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(existing_dir)]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "File encrypted successfully" not in out

    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(enc_file), "-o", str(existing_dir)]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "File decrypted successfully" not in out

    # 3. Output write raises PermissionError
    real_open = open

    def fail_perm_write(path, mode="r", *args, **kwargs):
        if "w" in mode:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_perm_write)
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(tmp_path / "out.gun101")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "Permission denied" in out
    assert "File encrypted successfully" not in out

    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(enc_file), "-o", str(tmp_path / "out.txt")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "Permission denied" in out
    assert "File decrypted successfully" not in out


def test_cli_filesystem_disk_full_error_paths(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source.txt"
    source.write_bytes(b"data to encrypt")
    enc_file = tmp_path / "source.gun101"
    enc_file.write_bytes(b"data to decrypt")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    monkeypatch.setattr(cli, "encrypt_file", lambda *_: b"sealed_content")
    monkeypatch.setattr(cli, "decrypt_file", lambda *_: b"recovered_content")
    real_open = open

    # 1. ENOSPC on open() for write during encrypt
    def enospc_open_write(path, mode="r", *args, **kwargs):
        if "w" in mode:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", enospc_open_write)
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(tmp_path / "out1.gun101")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "No space left on device" in out
    assert "File encrypted successfully" not in out

    # 2. ENOSPC on write() method during encrypt
    class MockFileENOSPC:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def write(self, data):
            raise OSError(errno.ENOSPC, "No space left on device")

    def enospc_write_method(path, mode="r", *args, **kwargs):
        if "w" in mode:
            return MockFileENOSPC()
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", enospc_write_method)
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(tmp_path / "out2.gun101")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "No space left on device" in out
    assert "File encrypted successfully" not in out

    # 3. ENOSPC on open() for write during decrypt
    monkeypatch.setattr("builtins.open", enospc_open_write)
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(enc_file), "-o", str(tmp_path / "out1.txt")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "No space left on device" in out
    assert "File decrypted successfully" not in out

    # 4. ENOSPC on write() method during decrypt
    monkeypatch.setattr("builtins.open", enospc_write_method)
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "decrypt", str(enc_file), "-o", str(tmp_path / "out2.txt")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "No space left on device" in out
    assert "File decrypted successfully" not in out

    # 5. Disk quota exceeded (EDQUOT / EFBIG)
    quota_errno = getattr(errno, "EDQUOT", errno.EFBIG)

    def edquot_open_write(path, mode="r", *args, **kwargs):
        if "w" in mode:
            raise OSError(quota_errno, "Quota exceeded or file too large")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", edquot_open_write)
    monkeypatch.setattr(
        sys, "argv", ["gun101tpm", "encrypt", str(source), "-o", str(tmp_path / "out3.gun101")]
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error writing output file:" in out
    assert "File encrypted successfully" not in out


def test_cli_non_leaking_error_messages(tmp_path, monkeypatch, capsys):
    secret_password = "ULTRA_SECRET_PASSWORD_CLI_12345"
    secret_content = b"TOP_SECRET_CONTENT_CLI_67890"

    source = tmp_path / "secret.txt"
    source.write_bytes(secret_content)
    monkeypatch.setenv("GUN101TPM_PASSWORD", secret_password)

    def assert_no_leaks(output: str):
        low = output.lower()
        assert "ultra_secret" not in low
        assert "12345" not in low
        assert "top_secret" not in low
        assert "67890" not in low

    # 1. Error during encryption
    monkeypatch.setattr(
        cli,
        "encrypt_file",
        lambda *_: (_ for _ in ()).throw(ValueError("Internal crypto error")),
    )
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit):
        cli.main()
    out, err = capsys.readouterr()
    assert_no_leaks(out + err)

    # 2. Error during decryption
    enc_file = tmp_path / "secret.gun101"
    enc_file.write_bytes(b"corrupted_encrypted_data")
    monkeypatch.setattr(
        cli,
        "decrypt_file",
        lambda *_: (_ for _ in ()).throw(ValueError("Decryption failed")),
    )
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(enc_file)])
    with pytest.raises(SystemExit):
        cli.main()
    out, err = capsys.readouterr()
    assert_no_leaks(out + err)

    # 3. Read failure
    real_open = open
    monkeypatch.setattr(
        "builtins.open",
        lambda path, mode="r", *a, **kw: (_ for _ in ()).throw(OSError("I/O failure"))
        if "r" in mode
        else real_open(path, mode, *a, **kw),
    )
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit):
        cli.main()
    out, err = capsys.readouterr()
    assert_no_leaks(out + err)

    # 4. Write failure
    monkeypatch.setattr(cli, "encrypt_file", lambda *_: b"sealed")
    monkeypatch.setattr(
        "builtins.open",
        lambda path, mode="r", *a, **kw: (_ for _ in ()).throw(OSError("Disk failure"))
        if "w" in mode
        else real_open(path, mode, *a, **kw),
    )
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    with pytest.raises(SystemExit):
        cli.main()
    out, err = capsys.readouterr()
    assert_no_leaks(out + err)


def test_cli_check_tpm_error_modes(monkeypatch, capsys):
    # 1. check_tpm_available raises NotImplementedError
    monkeypatch.setattr(
        cli,
        "check_tpm_available",
        lambda: (_ for _ in ()).throw(NotImplementedError("Backend not implemented")),
    )
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "check-tpm"])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error: Backend not implemented" in out

    # 2. check_tpm_available raises RuntimeError
    monkeypatch.setattr(
        cli,
        "check_tpm_available",
        lambda: (_ for _ in ()).throw(RuntimeError("TPM driver error")),
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error: TPM driver error" in out

    # 3. get_tpm_fingerprint raises RuntimeError
    monkeypatch.setattr(cli, "check_tpm_available", lambda: True)
    monkeypatch.setattr(
        cli,
        "get_tpm_fingerprint",
        lambda: (_ for _ in ()).throw(RuntimeError("Hardware read failure")),
    )
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Error reading TPM fingerprint: Hardware read failure" in out


def test_cli_overwrite_prompts_extended(tmp_path, monkeypatch, capsys):
    source = tmp_path / "overwrite_test.txt"
    source.write_bytes(b"content")
    target_enc = tmp_path / "overwrite_test.txt.gun101"
    target_enc.write_bytes(b"pre-existing")
    monkeypatch.setenv("GUN101TPM_PASSWORD", "password")
    monkeypatch.setattr(cli, "encrypt_file", lambda *_: b"new_encrypted_data")
    monkeypatch.setattr(cli, "decrypt_file", lambda *_: b"new_decrypted_data")

    # Test 'y' on encrypt overwrite prompt (branch 88->93)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "encrypt", str(source)])
    cli.main()
    out, _ = capsys.readouterr()
    assert f"File encrypted successfully: {target_enc}" in out
    assert target_enc.read_bytes() == b"new_encrypted_data"

    # Test 'n' on decrypt overwrite prompt (lines 138-139)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    monkeypatch.setattr(sys, "argv", ["gun101tpm", "decrypt", str(target_enc)])
    with pytest.raises(SystemExit) as err:
        cli.main()
    assert err.value.code == 1
    out, _ = capsys.readouterr()
    assert "Aborted." in out
