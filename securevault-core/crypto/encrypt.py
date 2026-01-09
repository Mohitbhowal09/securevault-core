import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256-GCM
KEY_SIZE = 32
NONCE_SIZE = 12

class CryptoError(Exception):
    """Generic Encryption/Decryption error."""
    pass

def generate_key() -> bytes:
    """Generates a random 32-byte key."""
    return AESGCM.generate_key(bit_length=256)

def generate_nonce() -> bytes:
    """Generates a random 12-byte nonce."""
    return os.urandom(NONCE_SIZE)

def encrypt_data(key: bytes, plaintext: bytes, associated_data: bytes = None) -> (bytes, bytes, bytes):
    """
    Encrypts plaintext using AES-256-GCM.
    Returns (nonce, ciphertext, tag).
    Note: cryptography's AESGCM.encrypt appends the tag to the ciphertext.
          We will separate them for clarity if requested, or keep strictly to library spec.
          The user spec asked for "Store: salt, ..., nonce, auth tag".
          The library output is ciphertext+tag. We can split it.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"Invalid key length: {len(key)}")
    
    try:
        aesgcm = AESGCM(key)
        nonce = generate_nonce()
        # encrypt() returns ciphertext + tag
        ct_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Split tag (last 16 bytes)
        tag_len = 16
        ciphertext = ct_and_tag[:-tag_len]
        tag = ct_and_tag[-tag_len:]
        
        return nonce, ciphertext, tag
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}")

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypts data using AES-256-GCM.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"Invalid key length: {len(key)}")
    
    try:
        aesgcm = AESGCM(key)
        # Reconstruct ciphertext + tag for the library
        ct_and_tag = ciphertext + tag
        
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, associated_data)
        return plaintext
    except Exception as e:
        # Cryptography raises InvalidTag if decryption fails
        raise CryptoError("Decryption failed: Integrity check failed or valid key/nonce mismatch.")
