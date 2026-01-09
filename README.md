# SecureVault

**Status**: Active Development (Phase 3 Complete)
**Current Version**: 0.3.0

SecureVault is an offline-first, zero-knowledge password manager and vault. It consists of a Python cryptographic core and a Chrome Extension for secure autofill.

## 📂 Repository Structure

- **`securevault-core/`**: The heart of the project.
  - **Crypto**: AES-256-GCM encryption, Argon2id KDF.
  - **Vault**: Manages encrypted items and Passkeys (WebAuthn).
  - **Native Host**: Bridges the browser extension to the python core.
- **`securevault-extension/`**: Chrome Extension (Manifest V3).
  - Handles login form detection and autofill.
  - Communicates securely with Core via Native Messaging.
- **`experimental/`**: Future proof-of-concept features (Desktop GUI, Installers) - *Not for production use*.

## ✅ Implemented Features

### Phase 1: Core Architecture
- [x] Secure local storage (JSON + AES-GCM).
- [x] Argon2id Key Derivation.
- [x] Zero-knowledge architecture (Master Password never stored).

### Phase 2: Encrypted Items
- [x] CRUD operations for Password Items.
- [x] CLI for vault management.

### Phase 3: Browser Integration
- [x] Chrome Extension (Popup & Content Script).
- [x] Native Messaging Host (`host.py`).
- [x] Secure Autofill.

### Phase 4: Mobile Apps (Experimental)
- [x] Android Crypto Implementation (Kotlin).
- [x] iOS Crypto Implementation (Swift).
- [ ] UI and Storage logic.

### Phase 5: Passkeys (WebAuthn)
- [x] Register Passkeys via Extension.
- [x] Passwordless Vault Unlock ("Release on Verified").
- [x] ECDSA Signature Verification in Core.

### Phase 6 & 7: Desktop & Installers (Experimental)
- [x] Electron GUI (Parked).
- [x] DMG/EXE Build Scripts (Parked).

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Google Chrome (for Extension)

### Installation
1. **Setup Core**:
   ```bash
   cd securevault-core
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 cli.py setup
   ```
   
2. **Install Native Host**:
   ```bash
   python3 install_host.py
   ```

3. **Load Extension**:
   - Open `chrome://extensions`
   - Enable "Developer Mode"
   - "Load Unpacked" -> Select `securevault-extension` folder.
   
4. **Configure Host ID**:
   - Copy the Extension ID from Chrome.
   - Edit the host manifest (path shown by `install_host.py`) to add the ID to `allowed_origins`.

## 🛡️ Security Model
- **Offline First**: No cloud sync. Secrets never leave your device.
- **Memory Safety**: Secrets are minimized in RAM and cleared on Lock.
- **Isolation**: The Chrome Extension cannot access the vault directly; it must request decryption via the Native Host (User Verification required).

## ⚠️ Experimental
Features in `experimental/` (Desktop GUI) are drafts and pending security review.
