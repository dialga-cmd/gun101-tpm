# Upgrade Guide

## Supported versions

The supported release line is `1.0.x`. Patch releases in this line are
intended to preserve the public CLI and Python API and to read containers using
the current `GUN-101-TPM` protocol version `2.0`.

Versions below `1.0` were development history and were not released to PyPI.
They are not supported upgrade sources.

Check the installed package and available release before upgrading:

```bash
python -m pip show gun101-tpm
python -m pip index versions gun101-tpm
```

## Standard package upgrade

For a normal patch or minor update within the supported line:

```bash
python -m pip install --upgrade gun101-tpm
gun101tpm check-tpm
python -m pytest tests/ -q
```

Keep the original TPM available and retain backups before upgrading. TPM-bound
files cannot be recovered if the TPM is lost, replaced, or inaccessible.

## Container-format changes

The encrypted container declares `protocol` and `version`. The current
software accepts only `GUN-101-TPM` protocol version `2.0`. A future release
that changes either value must document a migration in its changelog and
release notes.

If a future release cannot read an older container, use this safe migration:

1. Keep the old package installed in an isolated virtual environment.
2. On the original TPM, decrypt each old container to a temporary plaintext
   file.
3. Install the new package in a separate environment.
4. Encrypt the plaintext again with the new package and the intended password.
5. Verify decryption and file contents before deleting the old container or
   temporary plaintext.
6. Securely remove temporary plaintext files according to the host operating
   system's procedures.

Never delete the original container until the migrated container has been
successfully decrypted and verified. Never attempt to bypass a protocol or
version rejection by editing the JSON container.

## API and CLI changes

Public CLI and Python API changes are recorded in [CHANGELOG.md](../CHANGELOG.md)
and release notes. The external inputs and outputs are documented in the
[interface reference](INTERFACE.md). Read both documents before upgrading
automation or applications that import `gun101tpm.handler`.