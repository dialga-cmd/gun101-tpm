PROTOCOL = "GUN-101-TPM"
VERSION = "2.0"
DEK_LEN = 32                  # Data Encryption Key length
AES_NONCE_LEN = 12
SALT_LEN = 16                 # Argon2 salt length

# Argon2id parameters (OWASP recommended minimums for high-security)
ARGON2_TIME_COST = 3          # Number of iterations
ARGON2_MEMORY_COST = 65536    # Memory usage in KiB (64 MB)
ARGON2_PARALLELISM = 4        # Number of threads