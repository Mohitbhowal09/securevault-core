import sys
import os
import json

# Ensure we can import from sibling directories if run directly or as package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto import kdf, encrypt
from storage.vault_store import VaultStore
from app.items import PasswordItem

class VaultError(Exception):
    """Generic Vault logic error."""
    pass

class Vault:
    def __init__(self, storage_path: str):
        self.store = VaultStore(storage_path)
        self.vault_key = None  # The decrypted vault key (in memory only)
        self.items = []        # List of PasswordItem (in memory only)

    def is_unlocked(self) -> bool:
        return self.vault_key is not None

    def setup(self, master_password: str):
        """
        Initializes a new vault with the given master password.
        Flow:
        1. Generate Salt.
        2. Master Key = KDF(password, salt).
        3. Generate Vault Key (VK).
        4. Encrypt VK with Master Key.
        5. Initialize empty items list.
        6. Encrypt items list with VK.
        7. Save [Salt, Params, Encrypted VK, Encrypted Items] to storage.
        """
        if self.store.exists():
            raise VaultError("Vault already exists. Cannot overwrite.")

        try:
            # 1. Generate Salt
            salt = kdf.generate_salt()

            # 2. Derive Master Key
            master_key = kdf.derive_key(master_password, salt)

            # 3. Generate Vault Key
            vault_key = encrypt.generate_key()

            # 4. Encrypt Vault Key
            vk_nonce, vk_ciphertext, vk_tag = encrypt.encrypt_data(master_key, vault_key)

            # 5. Initialize empty items
            items_data = {"version": 1, "items": []}
            items_json = json.dumps(items_data).encode('utf-8')

            # 6. Encrypt items list with VK
            data_nonce, data_ciphertext, data_tag = encrypt.encrypt_data(vault_key, items_json)

            # 7. Prepare data
            data = {
                "version": 1,
                "kdf_params": kdf.get_params(),
                "salt": salt.hex(),
                
                # Encrypted Vault Key
                "nonce": vk_nonce.hex(),
                "ciphertext": vk_ciphertext.hex(),
                "tag": vk_tag.hex(),
                
                # Encrypted Data Blob
                "data_nonce": data_nonce.hex(),
                "data_ciphertext": data_ciphertext.hex(),
                "data_tag": data_tag.hex(),
                
                # Passkeys (Public data only)
                "passkeys": []
            }
            
            self.store.save(data)
            self.vault_key = vault_key
            self.items = []
            self.passkeys = []
            
            # Wipe master key from local variable (best effort)
            del master_key
            
        except Exception as e:
            raise VaultError(f"Setup failed: {e}")

    def unlock(self, master_password: str):
        """
        Unlocks the vault using password.
        """
        if not self.store.exists():
            raise VaultError("Vault does not exist.")

        try:
            data = self.store.load()
            
            # Extract KDF inputs
            salt = bytes.fromhex(data['salt'])
            vk_nonce = bytes.fromhex(data['nonce'])
            vk_ciphertext = bytes.fromhex(data['ciphertext'])
            vk_tag = bytes.fromhex(data['tag'])

            # Derive Master Key
            master_key = kdf.derive_key(master_password, salt)

            # Decrypt Vault Key
            self.vault_key = encrypt.decrypt_data(master_key, vk_nonce, vk_ciphertext, vk_tag)
            
            # Wipe master key
            del master_key

            # Load encrypted items
            if 'data_ciphertext' in data:
                self._load_items(data)
            else:
                self.items = [] # Handle legacy/empty vaults gracefully
                
            # Load passkeys
            self.passkeys = data.get('passkeys', [])
            
        except Exception as e:
            # It's crucial not to leak WHY it failed (key vs parsing), but usually it's AuthTag mismatch
            raise VaultError("Unlock failed. Invalid password or corrupted vault.")

    def unlock_with_passkey_secret(self, passkey_secret: bytes):
        """
        Unlocks the vault using a high-entropy secret retrieved via Passkey.
        This assumes we have a Wrapped Master Key or Wrapped Vault Key stored.
        
        For Phase 4, we need to implement the 'Key Wrapping' logic.
        Since we didn't initially store a wrapped key for passkeys, we need to add:
        register_passkey -> creates a random 'passkey_secret', WRAPS the Vault Key with it, 
                            and stores the 'passkey_secret' locally? 
                            NO, that defeats the purpose if stored in clear text.
                            
        The standard model: 
        1. User authenticates with Passkey.
        2. We verify signature.
        3. Logic: If signature valid, we release the Key?
           BUT the Key must be encrypted on disk. Who decrypts it?
           
        Strictly speaking, without a TPM-sealed key that only unseals on signature verification, 
        we can't cryptographically BIND the key to the passkey on a generic OS without platform specific APIs.
        
        However, the prompt asks for "Secure storage design notes" and "Protect private keys".
        It implies we verify the passkey and THEN unlock.
        To do this securely in software:
        We can store the Vault Key encrypted with a "Local Secret" that we only read into memory 
        IF the passkey verification succeeds. 
        OR, we just consider the "Passkey Verification" as the Gatekeeper.
        If `verify_assertion` == True, providing the code is trusted, we load the cached key?
        No, the key effectively shouldn't be in memory if locked.
        
        Compromise for Phase 4 (Software-based relying party):
        - We generate a random `passkey_token`.
        - We encrypt the `vault_key` with this `passkey_token`.
        - We store `encrypted_vault_key_by_passkey` in the vault data (publicly readable).
        - We store the `passkey_token` on disk, OBFUSCATED (e.g., split, or in a protected file).
        - When Passkey Auth succeeds, we de-obfuscate `passkey_token`, decrypt `vault_key`, and unlock.
        
        This satisfies "Release on Verified" simulation.
        """
        if not self.store.exists():
            raise VaultError("Vault does not exist.")

        try:
            data = self.store.load()
            
            # We look for 'wrapped_vk_passkey'
            wrapped_vk_hex = data.get('wrapped_vk_passkey')
            if not wrapped_vk_hex:
                 raise VaultError("No passkey setup for this vault.")
                 
            # Parse wrapper
            # Format: nonce|ciphertext|tag
            wrapped_blob = bytes.fromhex(wrapped_vk_hex)
            nonce = wrapped_blob[:12]
            tag = wrapped_blob[-16:]
            ciphertext = wrapped_blob[12:-16]
            
            # Decrypt Vault Key using the "Passkey Secret" (Token)
            self.vault_key = encrypt.decrypt_data(passkey_secret, nonce, ciphertext, tag)
            
            # Load items
            if 'data_ciphertext' in data:
                self._load_items(data)
            else:
                self.items = []
                
            self.passkeys = data.get('passkeys', [])
            
        except Exception as e:
            raise VaultError(f"Passkey Unlock failed: {e}")

    def register_passkey(self, credential_id: str, public_key_pem: str, user_handle: str):
        """
        Registers a verified passkey.
        Also generates the 'wrapped_vk_passkey' logic.
        MUST be unlocked to call this.
        """
        if not self.vault_key:
             raise VaultError("Vault must be unlocked to register passkey.")
             
        # 1. Store public credential
        self.passkeys.append({
            "id": credential_id,
            "public_key": public_key_pem,
            "user_handle": user_handle,
            "sign_count": 0
        })
        
        # 2. Key Wrapping Logic
        # Generate a strong random token (Passkey Secret)
        passkey_secret = os.urandom(32)
        
        # Encrypt the CURRENT Vault Key with this secret
        nonce, ciphertext, tag = encrypt.encrypt_data(passkey_secret, self.vault_key)
        
        # Store the wrapped key in the public vault data
        # We concatenate for simpler storage: nonce + ciphertext + tag
        wrapped_blob = nonce + ciphertext + tag
        
        # In a real app, we'd enable multiple passkeys to unwrap. For now, we support ONE active wrapper (last one wins).
        # Or better: Every passkey unlocks the SAME secret? No, simpler to just have one wrapper for now.
        
        # Save to disk
        data = self.store.load()
        data['passkeys'] = self.passkeys
        data['wrapped_vk_passkey'] = wrapped_blob.hex() 
        self.store.save(data)
        
        return passkey_secret # Return this so Host can store it obfuscated

    def lock(self):
        """
        Locks the vault by clearing the vault key and items from memory.
        """
        if self.vault_key:
            # Best effort overwrite (if it were bytearray, we could zero it. bytes is immutable).
            # We just drop the reference.
            self.vault_key = None
        self.items = []
        
        # Force garbage collection could be an option, but usually overkill/not guaranteed
        # import gc; gc.collect() 

    def _save_items(self):
        """Helper to encrypt and save current items to storage."""
        if not self.vault_key:
            raise VaultError("Vault is locked.")

        try:
            # Load existing wrapper to preserve KDF params & VK
            # We must READ from disk first to get the VK ciphertext/salt, 
            # because we don't store them in memory (we only have the decrypted VK).
            # Optimization: We could store the wrapper in memory, but re-reading is safer to avoid overwriting external changes?
            # For this simple app, re-reading is fine.
            data = self.store.load() 
            
            items_data = {
                "version": 1,
                "items": [item.to_dict() for item in self.items]
            }
            items_json = json.dumps(items_data).encode('utf-8')
            
            data_nonce, data_ciphertext, data_tag = encrypt.encrypt_data(self.vault_key, items_json)
            
            data['data_nonce'] = data_nonce.hex()
            data['data_ciphertext'] = data_ciphertext.hex()
            data['data_tag'] = data_tag.hex()
            
            self.store.save(data)
            
        except Exception as e:
            raise VaultError(f"Failed to save items: {e}")

    def _load_items(self, data: dict):
        """Helper to decrypt and parse items from loaded data dict."""
        if not self.vault_key:
            raise VaultError("Vault is locked.")
            
        try:
            data_nonce = bytes.fromhex(data['data_nonce'])
            data_ciphertext = bytes.fromhex(data['data_ciphertext'])
            data_tag = bytes.fromhex(data['data_tag'])
            
            items_json = encrypt.decrypt_data(self.vault_key, data_nonce, data_ciphertext, data_tag)
            items_data = json.loads(items_json.decode('utf-8'))
            
            self.items = [PasswordItem.from_dict(item) for item in items_data.get('items', [])]
            
        except Exception as e:
            raise VaultError(f"Failed to load items: {e}")

    # --- CRUD Operations ---

    def add_item(self, site: str, username: str, secret: str) -> None:
        if not self.is_unlocked():
            raise VaultError("Vault must be unlocked.")
            
        item = PasswordItem(site=site, username=username, secret=secret)
        self.items.append(item)
        self._save_items()

    def list_items(self) -> list[PasswordItem]:
        if not self.is_unlocked():
            raise VaultError("Vault must be unlocked.")
        return self.items

    def get_item(self, index: int) -> PasswordItem:
        if not self.is_unlocked():
            raise VaultError("Vault must be unlocked.")
        if 0 <= index < len(self.items):
            return self.items[index]
        raise VaultError(f"Item index {index} out of range.")
