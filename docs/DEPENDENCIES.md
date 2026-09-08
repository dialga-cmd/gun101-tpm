# Dependency Policy

GUN-101-TPM uses FLOSS dependencies selected for a specific security or build
role. Direct runtime dependencies and their minimum supported versions are
declared in `pyproject.toml` and are included in every source distribution and
wheel build.

## Direct dependencies

- `cryptography>=42.0.2` provides AES-256-GCM.
- `argon2-cffi>=23.1.0` provides Argon2id key derivation.
- `tpm2-pytss>=2.3.0` is an optional Linux-only dependency for TPM 2.0 access.
- `setuptools` provides the PEP 517 build backend.
- `build` creates the wheel and source distribution.
- `pytest`, Ruff, and Bandit are development and quality-assurance tools.

Dependencies are obtained from PyPI over HTTPS using standard Python package
management tools. Version floors are reviewed when security fixes or API
compatibility require an update. Dependency changes are reviewed in pull
requests, tested by GitHub Actions, and recorded in the changelog when they
affect users or security.

Dependabot checks the declared Python dependencies weekly:

https://github.com/dialga-cmd/gun101-tpm/network/updates

## Remediation thresholds

- Any known critical or high-severity dependency vulnerability blocks merges
	and releases until upgraded, patched, or documented as non-exploitable in a
	VEX record.
- Medium-severity vulnerabilities must be remediated before the next release;
	low-severity findings are triaged and scheduled according to exploitability.
- Dependencies with GPL, AGPL, or SSPL licenses are blocked unless the project
	explicitly approves the license impact before introduction.
- `pip-audit` and the license check run on every push, pull request, and
	release build. Violations fail the workflow.