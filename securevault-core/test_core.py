import os
import sys
import unittest

# Ensure imports work
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.vault import Vault, VaultError

TEST_FILE = "test_vault.dat"
MASTER_PWD = "correct_horse_battery_staple"

class TestSecureVault(unittest.TestCase):
    def setUp(self):
        # Clean up before test
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)
        self.vault = Vault(TEST_FILE)

    def tearDown(self):
        # Clean up after test
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)

    def test_full_flow(self):
        # 1. Setup
        print("\nTesting Setup...")
        self.vault.setup(MASTER_PWD)
        self.assertTrue(os.path.exists(TEST_FILE))
        self.assertTrue(self.vault.is_unlocked())
        original_vault_key = self.vault.vault_key
        self.assertIsNotNone(original_vault_key)
        self.assertEqual(len(original_vault_key), 32)
        
        # 2. Lock
        print("Testing Lock...")
        self.vault.lock()
        self.assertFalse(self.vault.is_unlocked())
        self.assertIsNone(self.vault.vault_key)
        
        # 3. Unlock with correct password
        print("Testing Unlock (Correct)...")
        self.vault.unlock(MASTER_PWD)
        self.assertTrue(self.vault.is_unlocked())
        self.assertEqual(self.vault.vault_key, original_vault_key)
        
        # 4. Lock again
        self.vault.lock()
        
        # 5. Unlock with WRONG password
        print("Testing Unlock (Wrong)...")
        with self.assertRaises(VaultError):
            self.vault.unlock("wrong_password")
        self.assertFalse(self.vault.is_unlocked())
        
        print("All checks passed.")

if __name__ == '__main__':
    unittest.main()
