# Secrets and Credentials Policy

## Storage

Secrets, tokens, passwords, private keys, certificates, and release credentials
MUST never be stored in Git, source files, issue reports, artifacts, or logs.
Local secret files such as `.env`, `*.key`, `*.pem`, `*.p12`, and credential
JSON files are ignored by `.gitignore`.

GitHub Actions credentials MUST be stored as GitHub encrypted secrets or OIDC
permissions. The project uses PyPI trusted publishing and keyless Sigstore so
that long-lived publishing keys are not stored in CI.

## Access

Secrets receive the least privilege needed by the job. Pull-request workflows
must not receive release or publishing credentials. Release credentials are
limited to the publishing job and are never printed or passed to untrusted
shell input.

## Rotation and exposure response

Maintainers rotate credentials immediately when exposure is suspected, revoke
the old credential before issuing its replacement, and record the incident in
the private security-report process. A leaked credential is treated as
compromised even if misuse has not been observed.

Report suspected exposure privately:

https://github.com/dialga-cmd/gun101-tpm/security/policy