# Release Verification

Each release contains the wheel, source distribution, `SHA256SUMS.txt`, and a
Sigstore bundle named `SHA256SUMS.sigstore.json`.

## Verify integrity

Download all release assets from the GitHub release page, then run:

```bash
sha256sum --check SHA256SUMS.txt
```

The command must report `OK` for every wheel and source archive.

## Verify authenticity

Install the FLOSS Sigstore `cosign` tool and verify the signed manifest:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/dialga-cmd/gun101-tpm/.github/workflows/publish.yml@refs/tags/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS.txt
```

The expected signer is the GitHub Actions `publish.yml` workflow in the
`dialga-cmd/gun101-tpm` repository. The workflow uses GitHub's OIDC identity
and Sigstore's public transparency log; no private signing key is stored in the
repository.

Release page:

https://github.com/dialga-cmd/gun101-tpm/releases