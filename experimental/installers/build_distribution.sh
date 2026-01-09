#!/bin/bash
set -e

# Build Script for SecureVault Distribution
# Usage: ./build_distribution.sh

echo ">>> Phase 1: Building Python Core..."
cd securevault-core
# Install deps (assuming venv active or available)
# pip install -r requirements.txt
# pip install pyinstaller

# Clean previous
rm -rf dist build

# Run PyInstaller
pyinstaller host.spec

echo ">>> Core Build Complete."
cd ..

echo ">>> Phase 2: Preparing Desktop..."
cd securevault-desktop
# Ensure electron-builder is installed
# npm install electron-builder --save-dev

echo ">>> Phase 3: Building Desktop App..."
# This relies on electron-builder.yml configuration
# It will pull the binary from ../securevault-core/dist/securevault-host
npm run dist

echo ">>> Build Complete! Installers are in securevault-desktop/dist/"
