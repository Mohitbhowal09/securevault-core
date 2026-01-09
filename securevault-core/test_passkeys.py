import os
import sys
import unittest
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

# Ensure imports work
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.vault import Vault
from app.webauthn_util import WebAuthnUtil

TEST_FILE = "test_passkey_vault.dat"
MASTER_PWD = "test_password"
USER_HANDLE = "user_handle_bytes"

class TestPasskeys(unittest.TestCase):
    def setUp(self):
        if os.path.exists(TEST_FILE):
             os.remove(TEST_FILE)
        self.vault = Vault(TEST_FILE)
        self.vault.setup(MASTER_PWD)
        
        # Generate a test EC Key Pair (Simulating Authenticator)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def tearDown(self):
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)

    def test_registration_and_auth_flow(self):
        print("\n--- Testing Passkey Flow ---")
        
        # 1. Register Passkey (while unlocked)
        print("Registering passkey...")
        credential_id = "cred_id_123"
        passkey_secret = self.vault.register_passkey(credential_id, self.public_key_pem, USER_HANDLE)
        
        self.assertIsNotNone(passkey_secret)
        self.assertTrue(len(self.passkeys_list()) > 0)
        
        # 2. Lock
        print("Locking vault...")
        self.vault.lock()
        self.assertFalse(self.vault.is_unlocked())
        
        # 3. Authenticate (Simulate)
        print("Simulating Authentication...")
        challenge = WebAuthnUtil.generate_challenge()
        client_data = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": "chrome-extension://..."}).encode('utf-8')
        client_data_hash = hashlib.sha256(client_data).digest()
        
        # Construct specific auth data (flags etc)
        # 32 byte hash + 1 byte flag + 4 byte counter = 37 bytes minimal
        rp_hash = b'\x00' * 32
        flags = b'\x05' # User Present + User Verified
        counter = b'\x00\x00\x00\x01'
        auth_data = rp_hash + flags + counter
        
        signed_message = auth_data + client_data_hash
        signature = self.private_key.sign(signed_message, ec.ECDSA(hashes.SHA256()))
        
        # 4. Verify using Utility
        print("Verifying signature...")
        # (This is what host.py does)
        target_pk = self.passkeys_list()[0]['public_key']
        valid = WebAuthnUtil.verify_assertion(target_pk, signature, client_data, auth_data)
        self.assertTrue(valid)
        
        # 5. Unlock using Secret
        print("Unlocking with secret...")
        self.vault.unlock_with_passkey_secret(passkey_secret)
        self.assertTrue(self.vault.is_unlocked())
        print("Unlocked successfully!")

    def passkeys_list(self):
        # Helper to read raw JSON for verification when locked
        with open(TEST_FILE, 'r') as f:
            data = json.load(f)
        return data.get('passkeys', [])
        
if __name__ == '__main__':
    unittest.main()
