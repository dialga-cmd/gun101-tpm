"""Portable unit tests for cryptography, handlers, and the CLI."""

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