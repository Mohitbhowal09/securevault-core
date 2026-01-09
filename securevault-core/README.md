# SecureVault Core

A minimal, offline-first, zero-knowledge password vault core implementation in Python.

## Features (Phase 1)
- **Zero Knowledge**: Your master password is never stored.
- **Strong Cryptography**:
    - **Argon2id** for Key Derivation (resistance against GPU/ASIC cracking).
    - **AES-256-GCM** for Authenticated Encryption.
- **Secure Storage**: 
    - Random 32-byte Vault Key encrypted by your Master Key.
    - 12-byte random nonces for every encryption.
    - Local-only storage.

## Installation

Prerequisites: Python 3.8+

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# (Or manually: pip install argon2-cffi cryptography)
```

## Usage

A CLI tool is provided for demonstration.

### 1. Setup
Create a new vault. You will be asked for a master password.
```bash
python3 cli.py setup
```
This generates `secure_vault.dat`.

### 2. Unlock
Test unlocking the vault.
```bash
python3 cli.py unlock
```
This verifies your password, derives the keys, decrypts the internal Vault Key, and then immediately locks it (wipes from memory) for this demo.

### 3. Reset
Delete the vault to start over.
```bash
python3 cli.py reset
```

## Architecture
- `crypto/`: Low-level cryptographic primitives.
- `storage/`: File I/O and JSON handling.
- `app/`: Core business logic (Setup, Unlock, Lock).
- `docs/`: Security documentation.

## Security Warning
This is a **Phase 1** core implementation. 
- Do not use for real secrets yet (there is no interface to add them!).
- It demonstrates the **Key Management Architecture**.
- If you lose your Master Password, **your data is lost forever**.
