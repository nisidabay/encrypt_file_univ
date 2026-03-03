#!/usr/bin/env python3

##############################################################################
# Author: nisidabay
# Name: enc_dec_file_univ.py
# Description: Encrypt and decrypt a file using key files or a password.
# Creation Date: vie 11 mar 2022 09:07:58 CET
# Modified Date: Thu 13 Nov 2025 12:00:00 PM UTC
# Version: 1.3
# Dependencies: See requirements.txt
##############################################################################
import sys
import shutil
import os
from pathlib import Path
from dataclasses import dataclass, field
from configparser import ConfigParser, NoSectionError, NoOptionError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Version markers
VERSION_KEYFILE = b'\x01'
VERSION_PASSWORD = b'\x02'

@dataclass
class EncryptFile:
    """Encrypt/Decrypt file using key files or password."""

    config_path: Path = field(default_factory=lambda: Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "pyencrypter")
    settings_path: Path = field(init=False)
    DEFAULT_KEY_NAME: str = "default.key"
    CHUNK_SIZE: int = 1024 * 1024  # 1MB chunks
    KDF_ITERATIONS: int = 600_000  # Number of iterations for PBKDF2

    def __post_init__(self) -> None:
        """Initialize settings path and ensure config directory exists."""
        self.config_path.mkdir(parents=True, exist_ok=True)
        self.settings_path = self.config_path.joinpath("settings.ini")

    def _initialize_project(self) -> None:
        """Creates settings.ini, a default key, and its backup."""
        print("[INFO] Initializing project with default configuration")

        # Create default key
        key_path = self.config_path.joinpath(self.DEFAULT_KEY_NAME)
        if not key_path.is_file():
            print(f"[INFO] Generating new encryption key: {self.DEFAULT_KEY_NAME}")
            with open(key_path, "wb") as fk:
                fk.write(base64.urlsafe_b64encode(os.urandom(32)))

        # Create settings.ini and set default key as default
        self._write_key_in_store(self.DEFAULT_KEY_NAME)

        # Backup default key
        backup_path = self.config_path.joinpath(f"{self.DEFAULT_KEY_NAME}.bak")
        if not backup_path.is_file():
            shutil.copy(key_path, backup_path)
            print(f"[INFO] Created backup: {self.DEFAULT_KEY_NAME}.bak")
            self._mk_key_readonly(f"{self.DEFAULT_KEY_NAME}.bak")

        self._mk_key_readonly(self.DEFAULT_KEY_NAME)

    def _mk_key_readonly(self, key: str) -> None:
        """Make the key read-only if not already set"""
        key_path = self.config_path.joinpath(key)
        if not key_path.is_file():
            return

        if sys.platform == "darwin" or sys.platform == "linux":
            try:
                key_path.chmod(0o400)
                print(f"Key secured: {Path(key_path).name}")
            except Exception as e:
                print(f"Failed to secure key {Path(key_path).name}: {e}")

    def change_key(self) -> None:
        """Change and load new key"""
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return
        try:
            self.show_active_key()
        except:
            pass
        new_key = input("Enter new key name: ")
        if not self.config_path.joinpath(new_key).is_file():
            print(f"Key '{new_key}' not found")
            sys.exit(1)
        self._write_key_in_store(new_key)
        print(f"Active key: {new_key}")

    def _write_key_in_store(self, key: str) -> None:
        """Write the key in settings.ini using configparser"""
        config = ConfigParser()
        config.read(self.settings_path)
        if not config.has_section("settings"):
            config.add_section("settings")
        config.set("settings", "key", key)
        with open(self.settings_path, "w") as configfile:
            config.write(configfile)

    def _get_active_key_name(self) -> str:
        """Get active key from settings.ini"""
        config = ConfigParser()
        config.read(self.settings_path)
        try:
            return config.get("settings", "key")
        except (NoSectionError, NoOptionError):
            if self._has_any_keys():
                print(f"[ERROR] Corrupted settings.ini file. Delete it to recreate: {e}")
                sys.exit(1)
            return ""

    def show_active_key(self) -> None:
        """Show active key"""
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return
        active_key = self._get_active_key_name()
        if active_key:
            print(f"Active key: {active_key}")
        else:
            print("No active key configured")

    def _load_raw_key(self) -> bytes:
        """Read and load the active key as raw bytes."""
        key_name = self._get_active_key_name()
        if not key_name:
             self._initialize_project()
             key_name = self._get_active_key_name()
        key_path = self.config_path.joinpath(key_name)
        if not key_path.is_file():
            print(f"Key '{key_name}' not found. Use -c to change key")
            sys.exit(1)
        with open(key_path, "rb") as fk:
            return base64.urlsafe_b64decode(fk.read())

    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive a 32-byte key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _file_exists(self, local_file: str) -> Path:
        """Check if the file to work on exists"""
        file_path = Path(local_file)
        if not file_path.exists():
            print(f"File '{local_file}' not found")
            sys.exit(1)
        return file_path

    def make_new_key(self) -> None:
        """Create a new key file."""
        new_key = input("Enter new key name: ")
        if not new_key.endswith(".key"):
            new_key += ".key"
        key_path = self.config_path.joinpath(new_key)
        if key_path.is_file():
            print(f"Key '{new_key}' already exists")
            sys.exit(1)
        with open(key_path, "wb") as fk:
            fk.write(base64.urlsafe_b64encode(os.urandom(32)))
            print(f"Key created: {new_key}")

    def make_key_readonly(self) -> None:
        """Make a key read-only"""
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return
        new_key = input("Enter the key name you want to make read-only: ")
        if not self.config_path.joinpath(new_key).is_file():
            print(f"Key '{new_key}' not found")
            sys.exit(1)
        self._mk_key_readonly(new_key)

    def encrypt(self, local_file: str, password: str | None = None) -> None:
        """Encrypt the file using either a key file or a password."""
        file_path = self._file_exists(local_file)
        output_file = f"{file_path.stem}.enc"

        iv = os.urandom(12)

        try:
            with open(file_path, "rb") as infile, open(output_file, "wb") as outfile:
                if password:
                    salt = os.urandom(16)
                    key = self._derive_key_from_password(password, salt)
                    outfile.write(VERSION_PASSWORD)
                    outfile.write(salt)
                else:
                    if not self._has_any_keys(): self._initialize_project()
                    key = self._load_raw_key()
                    outfile.write(VERSION_KEYFILE)

                outfile.write(iv)

                encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk: break
                    ciphertext = encryptor.update(chunk)
                    outfile.write(ciphertext)

                outfile.write(encryptor.finalize())
                outfile.write(encryptor.tag)

            print(f"File encrypted: {output_file}")
        except Exception as e:
            print(f"An error occurred during encryption: {e}")
            if Path(output_file).exists(): Path(output_file).unlink()
            sys.exit(1)

    def decrypt(self, local_file: str, password: str | None = None) -> None:
        """Decrypt the file using either a key file or a password."""
        file_path = self._file_exists(local_file)
        output_file = f"{file_path.stem}.dec"

        try:
            with open(file_path, "rb") as infile:
                version_byte = infile.read(1)

                header_len = 0
                # Handle legacy files without a version byte
                if version_byte not in [VERSION_KEYFILE, VERSION_PASSWORD]:
                    infile.seek(0)
                    key = self._load_raw_key()
                    iv = infile.read(12)
                    header_len = 12
                elif version_byte == VERSION_KEYFILE:
                    key = self._load_raw_key()
                    iv = infile.read(12)
                    header_len = 1 + 12
                elif version_byte == VERSION_PASSWORD:
                    if not password:
                        from getpass import getpass
                        password = getpass("Enter password: ")
                    if not password:
                        print("Password cannot be empty.")
                        sys.exit(1)
                    salt = infile.read(16)
                    key = self._derive_key_from_password(password, salt)
                    iv = infile.read(12)
                    header_len = 1 + 16 + 12

                infile.seek(-16, os.SEEK_END)
                tag = infile.read(16)

                infile.seek(header_len)

                decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

                with open(output_file, "wb") as outfile:
                    encrypted_data_size = file_path.stat().st_size - header_len - 16
                    bytes_read = 0
                    while bytes_read < encrypted_data_size:
                        chunk_size = min(self.CHUNK_SIZE, encrypted_data_size - bytes_read)
                        chunk = infile.read(chunk_size)
                        outfile.write(decryptor.update(chunk))
                        bytes_read += len(chunk)

                    outfile.write(decryptor.finalize())

        except InvalidTag:
            print("Invalid decryption key, password, or corrupted file.")
            if Path(output_file).exists(): Path(output_file).unlink()
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred during decryption: {e}")
            if Path(output_file).exists(): Path(output_file).unlink()
            sys.exit(1)

        print(f"File decrypted: {output_file}")

    def remove_key(self) -> None:
        """Remove selected key and its backup if it is the default key."""
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return
        rm_key = input("Enter the key name to remove: ")
        key_path = self.config_path.joinpath(rm_key)
        if not key_path.is_file():
            print(f"Key '{rm_key}' not found")
            sys.exit(1)

        if self._is_only_key_remaining(rm_key):
            print(f"[WARNING] '{rm_key}' is the only encryption key remaining!")
            if input("Are you sure you want to remove the last key? (y/n): ").lower().strip() not in ['y', 'yes']:
                print("Cancelled")
                return

        if self._get_active_key_name() == rm_key:
            self._blank_settings_file()
            print(f"Active key '{rm_key}' removed. Configuration reset.")

        # If it was the default key, also delete the backup
        if rm_key == self.DEFAULT_KEY_NAME:
            backup_path = self.config_path.joinpath(f"{self.DEFAULT_KEY_NAME}.bak")
            if backup_path.is_file():
                self._delete_key_file(backup_path)

        self._delete_key_file(key_path)
    def _blank_settings_file(self) -> None:
        """Blanks out the settings.ini file."""
        with open(self.settings_path, "w") as cf:
            cf.write("")

    def _delete_key_file(self, key_path: Path) -> None:
        """Deletes a key file, handling read-only permissions."""
        try:
            key_path.chmod(0o600)
            key_path.unlink()
            print(f"Key deleted: {key_path.name}")
        except Exception as e:
            print(f"Failed to delete key {key_path.name}: {e}")

    def _has_any_keys(self) -> bool:
        """Check if any .key files exist (excluding backups)"""
        return any(f for f in self.config_path.glob("*.key") if not f.name.endswith(".bak"))

    def _is_only_key_remaining(self, key_to_remove: str) -> bool:
        """Check if the specified key is the only .key file remaining"""
        keys = [f for f in self.config_path.glob("*.key") if not f.name.endswith(".bak")]
        return len(keys) == 1 and keys[0].name == key_to_remove

