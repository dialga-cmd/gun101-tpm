# Roadmap

This roadmap covers the next twelve months from the current 2026-09 release
line. Dates are targets, not promises; security and correctness take priority
over feature delivery.

## Completed

- [x] Linux TPM 2.0 support via `tpm2-pytss`.
- [x] Cross-platform backend architecture with an abstract interface.
- [x] Windows TBS backend for x64 and ARM64 availability checks and
	fingerprints.
- [x] Automated testing, static analysis, dependency auditing, and signed
	release-manifest workflow.

## Q4 2026: Release hardening

- [ ] Replace Windows software-emulated seal/unseal with genuine TPM 2.0 TBS
	sealing, including positive and negative hardware-backed tests.
- [ ] Add a second authorized maintainer and complete the continuity runbook.
- [ ] Reissue the current release with signed checksum and Sigstore assets.
- [ ] Review the container format and publish a migration policy before any
	incompatible format change.

## Q1-Q2 2027: Platform and assurance work

- [ ] Add reproducible `swtpm` integration tests for Linux CI.
- [ ] Implement and evaluate a macOS Secure Enclave backend, if its security
	properties can be documented and tested without weakening the Linux model.
- [ ] Evaluate optional PCR binding with an explicit threat-model update.
- [ ] Expand API and CLI coverage, including malformed input and filesystem
	error paths.

## Out of scope

- [ ] Password-only or portable decryption is not planned for the TPM-bound
	container format.
- [ ] A custom cryptographic primitive or custom key-derivation algorithm will
	not be implemented.
