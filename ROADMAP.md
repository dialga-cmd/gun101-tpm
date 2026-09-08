## Roadmap

- [x] Linux support (TPM 2.0 via tpm2-pytss)
- [x] Cross-platform backend architecture (backends/ package with abstract interface)
- [~] Windows support (**work in progress** — native TBS-based backend supports x64 and ARM64 via tbs.dll with `check-tpm`/fingerprint working, but seal/unseal is still software-emulated, not yet genuine TPM binding)
- [ ] macOS support (Secure Enclave-based backend — stub created, implementation not started; most Mac hardware has no TPM 2.0 chip, so this would be a different security backend, not a port of the TPM one)

No timelines — just record the intent so it reads as deliberate scoping, not an oversight.
