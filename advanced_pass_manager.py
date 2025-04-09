import sqlite3
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
import string
import secrets
from time import sleep
import json
from getpass import getpass

class SecurePasswordManager:
    def __init__(self):
        self.DB_FILE = "vault.db"
        self.KEY_FILE = ".key"
        self.SALT_FILE = ".salt"
        self.MAX_ATTEMPTS = 3
        self.CLIPBOARD_TIMEOUT = 30 # seconds

        if not os.path.exists(self.DB_FILE):
            self._init_db()

        if not os.path.exists(self.KEY_FILE):
            self._setup_master_password()

        self.cipher = self._load_cipher()

    def _init_db(self):
        """Initialize encrypted database"""
        conn = sqlite3.connect(self.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT DEFAULT '',
                last_updated TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _setup_master_password(self):
        """First-time setup with master password"""
        print("\n[!] First-time setup: Create Master Password")
        while True:
            master_pw = getpass("Create master password (min 12 chars): ")
            if len(master_pw) < 12:
                print("Password too short! Minimum 12 characters.")
                continue

            confirm_pw = getpass("Confirm master password: ")
            if master_pw != confirm_pw:
                print("Passwords don't match!")
                continue
        
            # Generate crypto materials
            salt = os.urandom(16)
            with open(self.SALT_FILE, "wb") as f:
                f.write(salt)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_pw.encode()))
            with open(self.KEY_FILE, "wb") as f:
                f.write(key)

            print("\n[+] Master password configured successfully!")
            break
    
    def _load_cipher(self):
        """Load encryption cipher after authentication"""
        attempts = 0
        while attempts < self.MAX_ATTEMPTS:
            master_pw = getpass("\nEnter master password: ")

            with open(self.SALT_FILE, "rb") as f:
                salt = f.read()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000
            )

            try:
                key = base64.urlsafe_b64encode(kdf.derive(master_pw.encode()))
                with open(self.KEY_FILE, "rb") as f:
                    if key != f.read():
                        raise ValueError("Wrong password")
                return Fernet(key)
            
            except:
                attempts += 1
                remaining = self.MAX_ATTEMPTS - attempts
                print(f"Invalid password! {remaining} attempts remaining.")
            
        print("[!] Maximum attempts reached. Exiting.")
        exit()
    
    def _encrypt(self, data):
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode())
    
    def _decrypt(self, encrypted_data):
        """Decrypt sensitive data"""
        return self.cipher.decrypt(encrypted_data).decode()

    def _generate_password(self, length=16):
        """Generate strong random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def _check_strength(self, password):
        """Analyze password strength"""
        score = 0
        if len(password) >= 12: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*" for c in password): score += 1
        return min(score, 5) # Max 5 stars
    
    def add_password(self):
        """Add new password entry"""
        service = input("\nService (e.g., Google): ").strip()
        username = input("Username/Email: ").strip()

        choice = input("Generate password? (y/n): ").lower()
        if choice == 'y':
            length = int(input("Password length (12-32): ") or 16)
            password = self._generate_password(length)
            print(f"Generated: {password}")
        else:
            while True:
                password = getpass("Enter password: ")
                strength = self._check_strength(password)
                print(f"Strength: {'★' * strength}{'☆' * (5 - strength)}")
                if strength >= 3 or input("Weak pasword! Continue? (y/n): ").lower() == 'y':
                    break

        notes = input("Notes (optional): ").strip()

        conn = sqlite3.connect(self.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (service, username, password, notes)
            VALUES (?, ?, ?, ?)
        ''', (
            service,
            username,
            self._encrypt(password),
            notes
        ))
        conn.commit()
        conn.close()
        print("\n[+] Password saved successfully!")

    def get_password(self, copy_to_clipboard=True):
        """Retrieve password"""
        service = input("\nService name: ").strip()

        conn = sqlite3.connect(self.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, password, notes FROM passwords 
            WHERE service = ?
        ''', (service,))
        result = cursor.fetchone()
        conn.close()

        if result:
            username, encrypted_password, notes = result
            password = self._decrypt(encrypted_password)

            print(f"\nService: {service}")
            print(f"Username: {username}")
            print(f"Notes: {notes}")

            if copy_to_clipboard:
                pyperclip.copy(password)
                print(f"\n[+] Password copied to clipboard (will clear in {self.CLIPBOARD_TIMEOUT}s.)")
                sleep(self.CLIPBOARD_TIMEOUT)
                pyperclip.copy("")
                print("[+] Clipboard cleared") 
            else:
                print(f"Password: {password}")
        else:
            print("[!] No password found for this service")

    def export_backup(self):
        """Export encrypted backup"""
        conn = sqlite3.connect(self.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords")
        data = cursor.fetchall()
        conn.close()

        backup = []
        for entry in data:
            backup.append({
                "id": entry[0],
                "service": entry[1],
                "username": entry[2],
                "password": entry[3],
                "notes": entry[4],
                "last_updated": entry[5]
            })
        
        filename = input("Backup filename (e.g., backup.json): ").strip()
        with open(filename, 'w') as f:
            json.dump(backup, f)
        print(f"[+] Backup saved to {filename}")

    def menu(self):
        """Main menu interface"""
        while True:
            print("\n" + "="*50)
            print("SECURE PASSWORD MANAGER".center(50))
            print("="*50)
            print("1. Add new password")
            print("2. Retrieve password")
            print("3. Generate strong password")
            print("4. Export backup")
            print("5. Exit")

            choice = input("\nSelect option (1-5): ")

            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.get_password()
            elif choice == '3':
                length = int(input("Password length (12-32): ") or 16)
                pw = self._generate_password(length)
                print(f"\nGenerated Password: {pw}")
                pyperclip.copy(pw)
                print(f"[+] Copied to clipboard (auto-clears in {self.CLIPBOARD_TIMEOUT}s)")
                sleep(self.CLIPBOARD_TIMEOUT)
                pyperclip.copy("")
            elif choice == '4':
                self.export_backup()
            elif choice == '5':
                print("\n[+] Vault locked. Goodbye!")
                break
            else:
                print("[!] Invalid choice")

if __name__ == "__main__":
    try:
        manager = SecurePasswordManager()
        manager.menu()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"\n[!] Critical error: {str(e)}")