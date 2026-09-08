---
name: Feature request
about: Suggest an improvement for GUN-101-TPM
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

## Description of the feature

<!-- What do you want GUN-101-TPM to do that it doesn't do today? -->

## Problem it solves / use case it enables

<!-- Who is affected and why does the current behaviour fall short?
  Concrete scenarios are very helpful. -->

## Proposed implementation approach

<!-- Optional but encouraged. Reference files/functions where relevant, e.g.
  `src/gun101tpm/backends/macos.py`, `src/gun101tpm/cli.py`'s
  `check-tpm` command. -->

## Security implications

- Does this touch **key derivation, encryption, or decryption**?
  - [ ] Yes
  - [ ] No

If yes, provide a written cryptographic justification: what the change does,
what property it preserves or strengthens, and why it cannot bypass the
hardware binding. Changes that shorten `ARGON2_*` parameters in
`src/gun101tpm/config.py`, weaken AES-256-GCM, or make containers decryptable
without the hardware module will not be accepted.

## Alternatives considered

<!-- What else did you consider, and why is this approach better? -->

## Checklist

- [ ] I have read [docs/SECURITY.md](../../docs/SECURITY.md) and this feature
      does **not** weaken any existing security guarantee.