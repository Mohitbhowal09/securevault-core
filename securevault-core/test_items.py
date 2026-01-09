import os
import sys
import unittest
import json

# Ensure imports work
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.vault import Vault, VaultError
from app.items import PasswordItem

TEST_FILE = "test_phase2_vault.dat"
MASTER_PWD = "correct_horse_battery_staple"

class TestPhase2(unittest.TestCase):
    def setUp(self):
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)
        self.vault = Vault(TEST_FILE)
        self.vault.setup(MASTER_PWD)

    def tearDown(self):
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)

    def test_item_encryption(self):
        print("\n--- Testing Item Encryption & Persistence ---")
        
        # 1. Add Item
        self.vault.add_item("example.com", "user1", "secret123")
        print("Item added.")

        # 2. Verify in memory
        items = self.vault.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].site, "example.com")
        self.assertEqual(items[0].secret, "secret123")

        # 3. Lock & Inspect File (No Plaintext)
        self.vault.lock()
        print("Vault locked.")
        
        with open(TEST_FILE, 'r') as f:
            content = f.read()
            # Ensure plaintext secrets are NOT in the file
            self.assertNotIn("example.com", content)
            self.assertNotIn("user1", content)
            self.assertNotIn("secret123", content)
            
            data = json.loads(content)
            self.assertIn("data_ciphertext", data)
            print("File inspection passed: No plaintext found, 'data_ciphertext' present.")

        # 4. Unlock & Verify Data
        self.vault.unlock(MASTER_PWD)
        print("Vault unlocked.")
        
        items = self.vault.list_items()
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.site, "example.com")
        self.assertEqual(item.username, "user1")
        self.assertEqual(item.secret, "secret123")
        print("Data integrity verified.")
        
    def test_multiple_items(self):
        print("\n--- Testing Multiple Items ---")
        self.vault.add_item("site1.com", "u1", "p1")
        self.vault.add_item("site2.com", "u2", "p2")
        
        self.vault.lock()
        self.vault.unlock(MASTER_PWD)
        
        items = self.vault.list_items()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].site, "site1.com")
        self.assertEqual(items[1].site, "site2.com")
        
        retrieved = self.vault.get_item(1)
        self.assertEqual(retrieved.secret, "p2")
        print("Multiple items verified.")

if __name__ == '__main__':
    unittest.main()
