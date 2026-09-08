## Description of the change

<!-- What does this PR do, and why? Reference issues/commits where relevant. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Security improvement
- [ ] Test addition
- [ ] Performance improvement

## Security review checklist

This library seals decryption keys inside TPM 2.0 hardware. Please read
[docs/SECURITY.md](../docs/SECURITY.md) and
[docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) before filling this in.

- [ ] This change does **not** reduce the Argon2id `time_cost`,
      `memory_cost`, or `parallelism` in `src/gun101tpm/config.py`
- [ ] This change does **not** reduce AES key length (32 bytes) or nonce
      length (12 bytes) in `src/gun101tpm/cipher.py`
- [ ] This change does **not** store the encryption key in plaintext on disk
- [ ] If this change touches key derivation, encryption, decryption, or the
      sealed container format, I have added a **written justification** in
      this PR description explaining the cryptographic reasoning
- [ ] This change does not reintroduce a device identifier / TPM fingerprint
      into the encrypted container
- [ ] All new code has type hints and docstrings
- [ ] I have added tests for any new functionality (positive **and** negative,
      where security-affecting)
- [ ] I have run `pytest tests/ -v` and all tests pass
      (if hardware tests could not run, say so explicitly and why)
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)

## Testing

<!-- Paste the relevant portion of `pytest tests/ -v` output, or explain
  clearly which hardware-dependent tests you could not run. -->

## Review readiness

- [ ] I have requested review from someone other than the author.
- [ ] CI, static analysis, dependency audit, and required coverage checks pass.
- [ ] Documentation, changelog, and migration notes are updated when needed.