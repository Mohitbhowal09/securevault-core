# Experimental / Future Phases

This directory contains code and configuration for phases of SecureVault that are currently **experimental** and **not production-ready**. They have been moved here to stabilize the core repository.

## Contents

### [mobile/](./mobile/) (Phase 4)
- **Status**: Concept / Crypto Scaffolds
- **Description**: Android (Kotlin) and iOS (Swift) implementations of the core cryptography.
- **Notes**: Demonstrates how to decrypt the standard SecureVault format on mobile devices using native APIs (`AndroidKeyStore`, `CryptoKit`).

### [desktop-gui/](./desktop-gui/) (Phase 6)
- **Status**: Alpha / Scaffold
- **Description**: An Electron-based desktop application.
- **Notes**: Contains the `main.js` process and `renderer` UI. Wired to spawn the Python Core.

### [installers/](./installers/) (Phase 7)
- **Status**: Planning / Config
- **Description**: Build scripts and configuration for packaging the application.
- **Notes**: 
    - `host.spec`: PyInstaller configuration.
    - `build_distribution.sh`: Build automation script.
    - **Usage**: You may need to adjust relative paths in these scripts as they were moved from the root.

## Usage
To work on these features, you may move them back to the root or update their path references to point to `../../securevault-core`.
