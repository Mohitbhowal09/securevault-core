# Threat Model: SecureVault Core (Phase 1)

## 1. Assets
- **Master Password**: The user's secret to unlock the vault.
- **Master Key**: Derived from the Master Password. Used to encrypt the Vault Key.
- **Vault Key**: Randomly generated key used to encrypt the actual vault contents (Secrets).
- **Secrets**: User passwords/data (Planned for Phase 2, but infrastructure exists).

## 2. Attacker Model
- **Remote Attacker**: Attackers over the internet.
    - *Mitigation*: This is an offline-only application. No network code.
- **Local Person**: Someone who steals the physical device or the vault file.
    - *Risk*: Brute-force attacks on the vault file.
    - *Mitigation*: Argon2id makes brute-force expensive.
- **Local Malware (User Space)**: A malicious process running as the user.
    - *Risk*: Memory scraping, Keylogging.
    - *Mitigation*: Key wiping (best effort). Keylogging is out of scope for Phase 1 (OS level protection needed).
- **Root/Admin**:
    - *Risk*: Total compromise.
    - *Mitigation*: Out of scope. If root is compromised, game over.

## 3. Attack Surfaces
### 3.1. Vault File
- **Description**: The encrypted `secure_vault.dat` stored on disk.
- **Threat**: Analysis of metadata, brute-force.
- **Mitigation**: Authenticated Encryption (AES-GCM). No plaintext metadata except KDF params (salt, construction parameters). Authentication tags prevent tampering.

### 3.2. Memory
- **Description**: RAM containing the decrypted Vault Key during operation.
- **Threat**: Cold boot attacks, core dumps, swap file analysis, malicious processes reading memory.
- **Mitigation**:
    - Keys are kept in memory only as long as needed.
    - Explicit `del` and overwriting references.
    - *Limitation*: Python's memory management (Garbage Collection) means we cannot guarantee immediate zeroization. Swap files are an OS-level concern (recommend Full Disk Encryption).

## 4. Cryptographic Primitives & Parameters
- **KDF**: Argon2id
    - `time_cost`: 2
    - `memory_cost`: 64 MiB
    - `parallelism`: 2
    - `salt`: 16 bytes CSPRNG
- **Encryption**: AES-256-GCM
    - `key`: 256-bit
    - `nonce`: 96-bit (12 bytes) CSPRNG
    - `tag`: 128-bit (16 bytes)

## 5. Accepted Risks (Phase 1)
- Python runtime memory persistence (GC).
- No integration with OS Keychain / TPM yet.
- Side-channel attacks on the device.
