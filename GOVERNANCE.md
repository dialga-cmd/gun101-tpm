# Project Governance and Access Roles

## Maintainer

**Aditya Raj** is the primary maintainer and release authority. The maintainer
reviews code, approves security-sensitive changes, manages releases, and
responds to private vulnerability reports.

## Sensitive repository access

Access to repository administration, branch protection, GitHub Actions release
permissions, and PyPI trusted publishing is restricted to repository
maintainers. The authoritative current membership and permission list is the
repository's GitHub access page:

https://github.com/dialga-cmd/gun101-tpm/settings/access

## Multi-factor authentication

All maintainers and collaborators with sensitive repository, release, or
security-report access must use GitHub two-factor authentication with a
cryptographic security key or passkey, or an authenticator application using
TOTP. SMS-only authentication is not sufficient for sensitive project access.

Repository owners must enable GitHub's organization or repository access
controls requiring two-factor authentication and periodically review account
security settings:

https://github.com/settings/security

Contributors receive only the permissions necessary for their work. Changes to
the protected `main` branch require reviewed pull requests and passing CI.

Before granting escalated access to repository administration, release
publishing, branch protection, or other sensitive resources, the maintainer
reviews the collaborator's identity, contribution history, intended duties,
and least-privilege requirements. Permission changes are made manually in
GitHub and recorded in the repository access history.

Continuity requirements and the current single-maintainer risk are documented
in the [continuity plan](docs/CONTINUITY.md). A backup maintainer must be
appointed before the project can claim a bus factor of two or full access
continuity.