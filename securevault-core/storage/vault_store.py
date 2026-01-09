import json
import os

class StorageError(Exception):
    """Generic Storage error."""
    pass

class VaultStore:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def save(self, data: dict):
        """
        Saves the vault data to disk as JSON.
        Data implies:
        {
            "version": 1,
            "kdf_params": {...},
            "nonce": hex_str,
            "ciphertext": hex_str,
            "tag": hex_str
        }
        """
        try:
            with open(self.file_path, 'w') as f:
                json.dump(data, f, indent=2)
            # Restrict permissions to owner only (approximate logical security)
            os.chmod(self.file_path, 0o600)
        except Exception as e:
            raise StorageError(f"Failed to save vault: {e}")

    def load(self) -> dict:
        """
        Loads the vault data from disk.
        """
        if not os.path.exists(self.file_path):
            raise StorageError("Vault file not found.")
            
        try:
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            raise StorageError(f"Failed to load vault: {e}")

    def exists(self) -> bool:
        return os.path.exists(self.file_path)
