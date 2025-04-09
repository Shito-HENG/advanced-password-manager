# Secure Password Manager 🔒

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Cryptography](https://img.shields.io/badge/Encryption-AES_256-yellow.svg)
![Security](https://img.shields.io/badge/Security-PBKDF2-red.svg)

A professional-grade password manager with military-grade encryption and secure storage.

## Features

- 🔐 **Master Password Protection** - PBKDF2 with 480,000 iterations
- 🛡️ **AES-256 Encryption** - Fernet authenticated cryptography
- 📋 **Secure Clipboard** - Auto-clears after 30 seconds
- 🔑 **Strong Password Generator** - Custom length (12-32 chars)
- 📦 **Encrypted Backups** - JSON export/import
- 📊 **Password Strength Meter** - 5-star rating system
- 💾 **SQLite Database** - Local encrypted storage

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/secure-password-manager.git
cd secure-password-manager

# Install dependencies
pip install cryptography pyperclip
```

## Usage
```bash
python advanced_pass_manager.py
```

## File Structure
```bash
.
├── vault.db            # Encrypted credential database
├── .key                # Master key derivation output
├── .salt               # Cryptographic salt (16 bytes)
└── backup_*.json       # Encrypted backup files
```
