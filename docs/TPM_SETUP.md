# TPM 2.0 Setup Guide — GUN-101-TPM

This guide explains how to set up a TPM 2.0 device for use with GUN-101-TPM.

## Prerequisites

- A TPM 2.0 hardware chip on your motherboard or a supported TPM simulator (swtpm)
- `tpm2-pytss` Python package installed
- Python 3.9+

## Enabling the TPM

1. **BIOS/UEFI Setup**: Restart your computer and enter the BIOS/UEFI settings. Enable the TPM 2.0 security device (often labeled as "TPM Security," "fTPM," "PTPM," or "PTT"). Save and exit.

2. **Operating System Setup**:
   - **Linux**: The TPM character device should appear at `/dev/tpm0` and `/dev/tpmrm0`. Ensure the `tss` group has read/write access:
     ```bash
     sudo usermod -aG tss $(whoami)
     newgrp tss
     ```
   - **Windows**: TPM is typically enabled via Windows Settings > Privacy > Trusted Platform Module.
   - **macOS**: TPM is available on Apple Silicon Macs via the Secure Enclave.

3. **Verify TPM Availability**: Run the following check:
   ```bash
   gun101tpm check-tpm
   ```
   This should output that a TPM 2.0 device was found, along with its fingerprint.

## Using a Software TPM Simulator (swtpm)

If you do not have a physical TPM 2.0 device, you can use the `swtpm` software simulator.

1. **Install swtpm**:
   ```bash
   apt-get install -y swtpm
   ```

2. **Start the TPM simulator**:
   ```bash
   swtpm --tcti mssim --daemon
   ```

3. **Verify the simulator is running**:
   ```bash
   swtpm status
   ```

4. **Run GUN-101-TPM commands**:
   ```bash
   gun101tpm check-tpm
   ```

## TPM Endorsement Key (EK) Fingerprint

GUN-101-TPM uses the TPM's Endorsement Key (EK) public area fingerprint to bind encrypted files to the machine. The fingerprint is a SHA-256 hash of the EK public area, formatted as a colon-separated uppercase hex string (32 groups of 2 hex digits).

The fingerprint is automatically generated and stored in the encrypted container during encryption. During decryption, it is checked first — if it doesn't match, the operation fails immediately without contacting the TMP.

## Troubleshooting

- **"TPM 2.0 device not found"**: Ensure the TPM is enabled in BIOS/UEFI, the `tss` group has access, and the `tpm2-pytss` package is installed.
- **"TPM unseal failed"**: This may indicate a different machine, wrong password, or corrupted sealed blob. Verify the TPM fingerprint matches and the correct password is used.
- **"Invalid sealed blob"**: The container may be corrupted. Re-encrypt the file if possible.

## Quick Start (with physical TPM)

```bash
# Check TPM
gun101tpm check-tpm

# Encrypt a file
gun101tpm encrypt mydocument.pdf

# Decrypt the same file (on the same machine)
gun101tpm decrypt mydocument.pdf.gun101
```

## Quick Start (with swtpm simulator)

```bash
# Start swtpm
swtpm --tcti mssim --daemon

# Check TPM
gun101tpm check-tpm

# Encrypt and decrypt as normal
gun101tpm encrypt mydocument.pdf
gun101tpm decrypt mydocument.pdf.gun101
```