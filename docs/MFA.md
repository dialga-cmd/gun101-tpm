# Secure Multi-Factor Authentication Policy

Access to sensitive project resources must use multi-factor authentication.
Sensitive resources include repository administration, protected branches,
release publishing, PyPI trusted publishing, GitHub Actions environments, and
private vulnerability reports.

## Approved factors

Maintainers and collaborators should use one of these mechanisms:

- FIDO2/WebAuthn security keys;
- passkeys backed by a device or hardware authenticator; or
- an authenticator application using TOTP.

SMS-only two-factor authentication is not accepted for sensitive project
access because SMS does not provide cryptographic resistance to impersonation
or number-porting attacks. SMS may be retained only as a recovery method when
GitHub requires it, never as the sole factor protecting project resources.

## Enforcement and recovery

Repository owners must require two-factor authentication for all collaborators
with sensitive access, review the access list periodically, and remove access
when it is no longer needed. Recovery codes and backup security keys must be
stored privately and never committed to the repository or placed in CI logs.

GitHub security settings:

https://github.com/settings/security

Repository access settings:

https://github.com/dialga-cmd/gun101-tpm/settings/access