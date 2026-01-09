#!/usr/bin/env python3
import sys
import os
import getpass
import argparse

# Ensure imports work
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.vault import Vault, VaultError

VAULT_FILE = "secure_vault.dat"

def get_password(prompt="Enter Master Password: ", confirm=False):
    while True:
        pwd = getpass.getpass(prompt)
        if not pwd:
            print("Password cannot be empty.")
            continue
        if confirm:
            pwd2 = getpass.getpass("Confirm Master Password: ")
            if pwd != pwd2:
                print("Passwords do not match. Try again.")
                continue
        return pwd

def main():
    parser = argparse.ArgumentParser(description="SecureVault Core CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Setup command
    subparsers.add_parser("setup", help="Initialize a new vault")
    
    # Unlock command
    subparsers.add_parser("unlock", help="Unlock the vault (test unlock)")

    # Status command
    subparsers.add_parser("status", help="Check vault status")
    
    # Reset command
    # Reset command
    subparsers.add_parser("reset", help="Delete the local vault file")

    # Add Item command
    add_parser = subparsers.add_parser("add", help="Add a new password item")
    add_parser.add_argument("--site", required=True, help="Site name (e.g. google.com)")
    add_parser.add_argument("--username", required=True, help="Username")
    
    # List Items command
    subparsers.add_parser("list", help="List all items")
    
    # Get Item command
    get_parser = subparsers.add_parser("get", help="Get item details")
    get_parser.add_argument("index", type=int, help="Item index (from list)")

    args = parser.parse_args()
    
    vault = Vault(VAULT_FILE)

    if args.command == "setup":
        if os.path.exists(VAULT_FILE):
            print("Vault already exists. Use 'reset' to delete it first.")
            return
        
        print("Creating new SecureVault...")
        password = get_password(confirm=True)
        try:
            vault.setup(password)
            print(f"Vault created successfully at '{VAULT_FILE}'.")
            print("Internal Vault Key generated and encrypted.")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == "unlock":
        if not os.path.exists(VAULT_FILE):
            print("No vault found. Run 'setup' first.")
            return

        print("Unlocking SecureVault...")
        password = get_password()
        try:
            vault.unlock(password)
            print("Success! Vault unlocked.")
            print(f"Vault Key in memory: {vault.vault_key.hex()[:8]}... (redacted)")
            
            # Immediately lock for safety in this CLI demo
            # vault.lock() # Removal: In a real CLI session we might want to keep it open? 
            # Actually, standard CLI strictly does one op and exit.
            # But 'unlock' command alone is just a test.
            # The add/list/get commands will do their own unlock flow.
            # So I will keep the lock here to show safety.
            vault.lock()
            print("Vault locked.")
        except VaultError:
            print("Error: Invalid password or corrupted vault.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    elif args.command == "add":
        if not os.path.exists(VAULT_FILE):
            print("No vault found. Run 'setup' first.")
            return

        print("Unlocking to add item...")
        password = get_password()
        try:
            vault.unlock(password)
            
            secret = getpass.getpass(f"Enter password for {args.username}@{args.site}: ")
            if not secret:
                print("Password cannot be empty.")
                return
                
            vault.add_item(args.site, args.username, secret)
            print("Item added successfully.")
            
        except VaultError:
            print("Error: Unlock failed.")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == "list":
        if not os.path.exists(VAULT_FILE):
            print("No vault found. Run 'setup' first.")
            return

        print("Unlocking to list items...")
        password = get_password()
        try:
            vault.unlock(password)
            items = vault.list_items()
            
            if not items:
                print("No items found.")
            else:
                print(f"\n{'IDX':<5} | {'SITE':<20} | {'USERNAME':<30}")
                print("-" * 60)
                for idx, item in enumerate(items):
                    print(f"{idx:<5} | {item.site:<20} | {item.username:<30}")
            print("")
            
        except VaultError:
            print("Error: Unlock failed.")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == "get":
        if not os.path.exists(VAULT_FILE):
            print("No vault found. Run 'setup' first.")
            return

        print("Unlocking to retrieve item...")
        password = get_password()
        try:
            vault.unlock(password)
            item = vault.get_item(args.index)
            
            print("\n--- Item Details ---")
            print(f"Site:     {item.site}")
            print(f"Username: {item.username}")
            print(f"Password: {item.secret}")
            print(f"Created:  {item.created_at}")
            print("--------------------")
            
        except VaultError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == "status":
        if os.path.exists(VAULT_FILE):
            print(f"Vault file found at '{VAULT_FILE}'.")
        else:
            print("No vault file found.")

    elif args.command == "reset":
        if os.path.exists(VAULT_FILE):
            confirm = input(f"Are you sure you want to delete '{VAULT_FILE}'? This cannot be undone. [y/N] ")
            if confirm.lower() == 'y':
                os.remove(VAULT_FILE)
                print("Vault deleted.")
            else:
                print("Cancelled.")
        else:
            print("No vault to delete.")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
