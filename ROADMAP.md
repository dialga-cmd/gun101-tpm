## Roadmap

- [x] Linux support (TPM 2.0 via tpm2-pytss)
- [x] Cross-platform backend architecture (backends/ package with abstract interface)
- [x] Windows support (native TBS-based backend — supports both x64 and ARM64 Windows devices via tbs.dll)
- [ ] macOS support (Secure Enclave-based backend — stub created, implementation not started; most Mac hardware has no TPM 2.0 chip, so this would be a different security backend, not a port of the TPM one)

No timelines — just record the intent so it reads as deliberate scoping, not an oversight.
