"""
Command-line interface for GUN-101-TPM.
"""

import argparse
import sys
import os
import getpass
from .handler import encrypt_file, decrypt_file
from .backends import check_tpm_available, get_tpm_fingerprint


def get_password() -> str:
    """Get password from env var or interactive prompt."""
    password = os.environ.get("GUN101TPM_PASSWORD")
    if not password:
        password = getpass.getpass("Password: ")
    if os.environ.get("GUN101TPM_PASSWORD") and password == os.environ["GUN101TPM_PASSWORD"]:
        print("WARNING: Using password from environment variable. "
              "This is less secure — password may appear in shell history or process listing.")
    return password


def main():
    parser = argparse.ArgumentParser(
        description="GUN-101-TPM: Hardware-bound file encryption using TPM 2.0"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # check-tpm command
    parser_check = subparsers.add_parser(
        "check-tpm", help="Check if a TPM 2.0 device is available"
    )

    # encrypt command
    parser_encrypt = subparsers.add_parser(
        "encrypt", help="Encrypt a file"
    )
    parser_encrypt.add_argument(
        "file", help="Path to the file to encrypt"
    )
    parser_encrypt.add_argument(
        "-o", "--output", help="Output file path (default: input.gun101)"
    )

    # decrypt command
    parser_decrypt = subparsers.add_parser(
        "decrypt", help="Decrypt a file"
    )
    parser_decrypt.add_argument(
        "file", help="Path to the file to decrypt"
    )
    parser_decrypt.add_argument(
        "-o", "--output", help="Output file path (default: input.decrypted)"
    )

    args = parser.parse_args()

    if args.command == "check-tpm":
        try:
            if check_tpm_available():
                try:
                    fingerprint = get_tpm_fingerprint()
                    print(f"TPM 2.0 device found. Fingerprint: {fingerprint}")
                except Exception as e:
                    print(f"Error reading TPM fingerprint: {e}")
                    sys.exit(1)
        except (RuntimeError, NotImplementedError) as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "encrypt":
        if not os.path.isfile(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)

        # Determine output file
        if args.output:
            output_path = args.output
        else:
            output_path = args.file + ".gun101"

        # Check if output file exists
        if os.path.exists(output_path):
            response = input(f"File '{output_path}' already exists. Overwrite? [y/N] ")
            if response.lower() != 'y':
                print("Aborted.")
                sys.exit(1)

        # Read file
        try:
            with open(args.file, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

        # Prompt for password
        password = get_password()

        # Encrypt
        try:
            encrypted = encrypt_file(data, password)
        except Exception as e:
            print(f"Error during encryption: {e}")
            sys.exit(1)

        # Write output
        try:
            with open(output_path, "wb") as f:
                f.write(encrypted)
            print(f"File encrypted successfully: {output_path}")
        except OSError as e:
            print(f"Error writing output file: {e}")
            sys.exit(1)

    elif args.command == "decrypt":
        if not os.path.isfile(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)

        # Determine output file
        if args.output:
            output_path = args.output
        else:
            # Remove .gun101 extension if present, else append .decrypted
            if args.file.endswith(".gun101"):
                output_path = args.file[:-7]
            else:
                output_path = args.file + ".decrypted"

        # Check if output file exists
        if os.path.exists(output_path):
            response = input(f"File '{output_path}' already exists. Overwrite? [y/N] ")
            if response.lower() != 'y':
                print("Aborted.")
                sys.exit(1)

        # Read file
        try:
            with open(args.file, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

        # Prompt for password
        password = get_password()

        # Decrypt
        try:
            decrypted = decrypt_file(data, password)
        except Exception as e:
            print(f"Error during decryption: {e}")
            sys.exit(1)

        # Write output
        try:
            with open(output_path, "wb") as f:
                f.write(decrypted)
            print(f"File decrypted successfully: {output_path}")
        except OSError as e:
            print(f"Error writing output file: {e}")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()