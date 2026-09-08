# Copyright (c) 2026 GUN-101-TPM contributors
# SPDX-License-Identifier: MIT

"""Portable unit tests for cryptography, handlers, and the CLI."""

import base64
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