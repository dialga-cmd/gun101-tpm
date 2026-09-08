---
name: Bug report
about: Report a reproducible problem with GUN-101-TPM
title: "[BUG] "
labels: bug
assignees: ''
---

> Security vulnerability? Do **not** open a public issue. Email
> adityaraj1234@duck.com instead — see [SECURITY_POLICY.md](../../SECURITY_POLICY.md).

## Description of the bug

<!-- What happened, and what did you expect instead? -->

## Steps to reproduce

<!-- Exact CLI command or minimal Python snippet. -->

```bash
gun101tpm encrypt path/to/file.pdf
# or
```

```python
from gun101tpm.handler import encrypt_file, decrypt_file
```

1.
2.
3.

## Expected behaviour

<!-- What did you expect to happen? -->

## Actual behaviour

<!-- Include the exact error message, including full traceback if available. -->

```
(paste exact error output here)
```

## Environment

- OS: <!-- e.g. Linux (Ubuntu 24.04), Windows 11, macOS; include TPM setup
  (physical /dev/tpm0, swtpm, none) -->
- Python version: <!-- e.g. 3.11.9, 3.12.2 -->
- Library version: <!-- output of `pip show gun101-tpm` -->
- Backend in use: <!-- Linux (TPM), Windows (TBS), macOS, or the
  error from `gun101tpm check-tpm` -->

## Additional context

<!-- Anything else relevant: YES, e.g. recent git commit, modified container
files, hardware details. -->

## Checklist

- [ ] I have checked that this is **not** a known limitation documented in
      [docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md) or
      [docs/SECURITY.md](../../docs/SECURITY.md) (for example: decryption
      failing on a different machine, permanent data loss if the TPM fails,
      or no cross-device portability are **by design**, not bugs).