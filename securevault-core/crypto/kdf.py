import os
from argon2.low_level import hash_secret_raw, Type, ARGON2_VERSION

# Constants for KDF
# OWASP cheat sheet recommends:
# - Argon2id
# - memory: 64 MiB (65536 KiB)
# - iterations: 2 (or more, tuned to system)
# - parallelism: 1 or more (2 is often good for dual core)
# We will use robust defaults for a password manager vault.

KDF_SALT_LEN = 16
KDF_KEY_LEN = 32  # 256 bits for AES-256
KDF_TIME_COST = 2
KDF_MEMORY_COST = 65536  # 64 MiB
KDF_PARALLELISM = 2

class KDFError(Exception):
    """Generic KDF error."""
    pass

def generate_salt() -> bytes:
    """Generates a random salt."""
    return os.urandom(KDF_SALT_LEN)

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte key from the password and salt using Argon2id.
    """
    if not isinstance(password, str):
        raise KDFError("Password must be a string")
    if not isinstance(salt, bytes):
        raise KDFError("Salt must be bytes")
    if len(salt) != KDF_SALT_LEN:
        raise KDFError(f"Salt must be {KDF_SALT_LEN} bytes")

    try:
        # Note: password must be encoded to bytes for low_level
        secret = password.encode('utf-8')
        
        derived_key = hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=KDF_TIME_COST,
            memory_cost=KDF_MEMORY_COST,
            parallelism=KDF_PARALLELISM,
            hash_len=KDF_KEY_LEN,
            type=Type.ID,
            version=ARGON2_VERSION
        )
        return derived_key
    except Exception as e:
        raise KDFError(f"Key derivation failed: {e}")

def get_params():
    """Returns the KDF parameters used."""
    return {
        "algorithm": "argon2id",
        "time_cost": KDF_TIME_COST,
        "memory_cost": KDF_MEMORY_COST,
        "parallelism": KDF_PARALLELISM,
        "hash_len": KDF_KEY_LEN
    }
