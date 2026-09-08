# Vulnerability Exploitability (VEX) Policy

The project tracks dependency vulnerabilities reported by `pip-audit` and
maintainer review. If a vulnerable component does not affect GUN-101-TPM, the
project records a VEX statement before suppressing or releasing around the
finding.

A VEX record includes:

- the affected component and version;
- the vulnerability identifier;
- the affected project release;
- the VEX status (`not affected`, `affected`, or `under investigation`);
- technical reasoning explaining exploitability or non-exploitability;
- compensating controls and the review date; and
- the maintainer approving the disposition.

VEX records are published with the relevant security advisory or release
documentation when disclosure is appropriate. No dependency vulnerability is
silently suppressed in CI.

Security advisories:

https://github.com/dialga-cmd/gun101-tpm/security/advisories