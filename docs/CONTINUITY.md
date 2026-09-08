# Project Continuity Plan

## Current status

The project currently has one documented primary maintainer, Aditya Raj. This
is a continuity risk: the repository should not be considered fully resilient
to the maintainer becoming unavailable until a second authorized maintainer is
appointed.

## Required continuity arrangement

The maintainer must appoint at least one backup maintainer with:

- GitHub write and administration access sufficient to manage issues and
  protected-branch reviews;
- permission to approve and merge pull requests;
- access to the GitHub Actions release environment and PyPI trusted publisher;
- authority to coordinate private vulnerability reports; and
- the legal authority needed to continue distribution under the MIT license.

Long-lived secrets are intentionally avoided. GitHub MFA, branch protection,
PyPI trusted publishing, and Sigstore OIDC should be transferred or jointly
administered rather than sharing passwords or private keys.

## Seven-day recovery procedure

After confirming the primary maintainer is unavailable, the backup maintainer
should, within seven days:

1. Confirm access to GitHub, protected `main`, issues, and pull requests.
2. Confirm PyPI trusted publishing and GitHub Actions release permissions.
3. Review open security reports privately and acknowledge them.
4. Run the documented test, audit, and build workflows.
5. Publish a maintenance update and appoint another backup maintainer.

The authoritative access list is maintained in GitHub repository settings:

https://github.com/dialga-cmd/gun101-tpm/settings/access