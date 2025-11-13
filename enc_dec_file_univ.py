#!/usr/bin/env python3

##############################################################################
# Author: nisidabay
# Name: enc_dec_file_univ.py
# Description: Encrypt and decrypt a file using Fernet encryption
# Creation Date: vie 11 mar 2022 09:07:58 CET
# Modified Date: Thu 13 Nov 2025 12:00:00 PM UTC
# Modified Date: Thu Nov 13 11:22:53 AM CET 2025
# Version: 1.2
# Dependencies: See requirements.txt
##############################################################################
import sys
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from configparser import ConfigParser, NoSectionError, NoOptionError
from cryptography.fernet import Fernet, InvalidToken


@dataclass
class EncryptFile:
    """Encrypt/Decrypt file using Fernet"""

    script_path: Path = field(default_factory=lambda: Path(__file__).parent.absolute())
    settings_path: Path = field(init=False)
    DEFAULT_KEY_NAME: str = "default.key"

    def __post_init__(self) -> None:
        """Initialize settings path."""
        self.settings_path = self.script_path.joinpath("settings.ini")

    def _initialize_project(self) -> None:
        """Creates settings.ini, a default key, and its backup."""
        print("[INFO] Initializing project with default configuration")

        # Create default key
        key_path = self.script_path.joinpath(self.DEFAULT_KEY_NAME)
        if not key_path.is_file():
            print(f"[INFO] Generating new encryption key: {self.DEFAULT_KEY_NAME}")
            with open(key_path, "wb") as fk:
                fk.write(Fernet.generate_key())

        # Create settings.ini and set default key as default
        self._write_key_in_store(self.DEFAULT_KEY_NAME)

        # Backup default key
        backup_path = self.script_path.joinpath(f"{self.DEFAULT_KEY_NAME}.bak")
        if not backup_path.is_file():
            shutil.copy(key_path, backup_path)
            print(f"[INFO] Created backup: {self.DEFAULT_KEY_NAME}.bak")
            self._mk_key_readonly(f"{self.DEFAULT_KEY_NAME}.bak")

        self._mk_key_readonly(self.DEFAULT_KEY_NAME)

    def _mk_key_readonly(self, key: str) -> None:
        """Make the key read-only if not already set"""
        key_path = self.script_path.joinpath(key)
        if not key_path.is_file():
            return

        if sys.platform == "darwin":
            self._key_mac(str(key_path))
        elif sys.platform == "linux":
            self._key_linux(str(key_path))

    def _key_mac(self, key_path: str) -> None:
        """Set the key to be read-only on macOS."""
        try:
            # Set the file permissions to read-only for the owner
            Path(key_path).chmod(0o400)
            print(f"Key secured: {Path(key_path).name}")
        except Exception as e:
            print(f"Failed to secure key {Path(key_path).name}: {e}")

    def _key_linux(self, key_path: str) -> None:
        """Set the key to be read-only on Linux."""
        try:
            # Set the file permissions to read-only for the owner
            Path(key_path).chmod(0o400)
            print(f"Key secured: {Path(key_path).name}")
        except Exception as e:
            print(f"Failed to secure key {Path(key_path).name}: {e}")

    def change_key(self) -> None:
        """Change and load new key"""
        # Check if any keys exist
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return

        # Show current active key if available
        try:
            self.show_active_key()
        except:
            pass

        new_key = input("Enter new key name: ")
        if not self.script_path.joinpath(new_key).is_file():
            print(f"Key '{new_key}' not found")
            sys.exit(1)
        self._write_key_in_store(new_key)
        print(f"Active key: {new_key}")

    def _write_key_in_store(self, key: str) -> None:
        """Write the key in settings.ini using configparser"""
        config = ConfigParser()
        # Read the file if it exists, otherwise we'll create it.
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
        except (NoSectionError, NoOptionError) as e:
            # If we're in a context where keys should exist, this is an error
            # Otherwise, let initialization handle it
            if self._has_any_keys():
                print(
                    f"[ERROR] Corrupted settings.ini file. Delete it to recreate: {e}"
                )
                sys.exit(1)
            else:
                # This will trigger initialization on next operation that needs a key
                return ""

    def show_active_key(self) -> None:
        """Show active key"""
        # Check if any keys exist
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return

        active_key = self._get_active_key_name()
        if active_key:
            print(f"Active key: {active_key}")
        else:
            print("No active key configured")

    def _load_key(self) -> Fernet:
        """Read and load the Personal key"""
        key_name = self._get_active_key_name()
        key_path = self.script_path.joinpath(key_name)
        if not key_path.is_file():
            print(f"Key '{key_name}' not found. Use -c to change key")
            sys.exit(1)
        with open(key_path, "rb") as fk:
            return Fernet(fk.read())

    def _file_exists(self, local_file: str) -> Path:
        """Check if the file to work on exists"""
        file_path = Path(local_file)
        if not file_path.exists():
            print(f"File '{local_file}' not found")
            sys.exit(1)
        return file_path

    def make_new_key(self) -> None:
        """Create a new key"""
        new_key = input("Enter new key name: ")
        if not new_key.endswith(".key"):
            new_key += ".key"
        key_path = self.script_path.joinpath(new_key)
        if key_path.is_file():
            print(f"Key '{new_key}' already exists")
            sys.exit(1)
        with open(key_path, "wb") as fk:
            fk.write(Fernet.generate_key())
            print(f"Key created: {new_key}")

    def make_key_readonly(self) -> None:
        """Make a key read-only"""
        # Check if any keys exist
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return

        new_key = input("Enter the key name you want to make read-only: ")
        if not self.script_path.joinpath(new_key).is_file():
            print(f"Key '{new_key}' not found")
            sys.exit(1)
        self._mk_key_readonly(new_key)

    def encrypt(self, local_file: str) -> None:
        """Encrypt the file"""
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return
        file_path = self._file_exists(local_file)
        with open(file_path, "rb") as file_to_read:
            encrypted_file = self._load_key().encrypt(file_to_read.read())
            with open(f"{file_path.stem}.enc", "wb") as encoded_file:
                encoded_file.write(encrypted_file)
            print(f"File encrypted: {file_path.stem}.enc")

    def decrypt(self, local_file: str) -> None:
        """Decrypt the file"""
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return
        file_path = self._file_exists(local_file)
        try:
            with open(file_path, "rb") as file_to_read:
                decrypted_file = self._load_key().decrypt(file_to_read.read())
                with open(f"{file_path.stem}.dec", "wb") as decoded_file:
                    decoded_file.write(decrypted_file)
        except InvalidToken:
            print(
                "Invalid decryption key. File may have been encrypted with a different key"
            )
            sys.exit(1)
        print(f"File decrypted: {file_path.stem}.dec")
        file_path.unlink()

    def remove_key(self) -> None:
        """Remove selected key and its backup if it is the default key."""
        # Check if any keys exist at all
        if not self._has_any_keys():
            print("No key found. Create a key first")
            return

        rm_key = input("Enter the key name to remove: ")

        key_path = self.script_path.joinpath(rm_key)
        if not key_path.is_file():
            print(f"Key '{rm_key}' not found")
            sys.exit(1)

        # Check if this is the only remaining key
        if self._is_only_key_remaining(rm_key):
            print(f"[WARNING] '{rm_key}' is the only encryption key remaining!")
            print(
                "[WARNING] Removing it will leave you unable to decrypt existing files"
            )
            confirmation = (
                input("Are you sure you want to remove the last key? (yes/no): ")
                .lower()
                .strip()
            )
            if confirmation not in ["yes", "y"]:
                print("Cancelled")
                return

        # Check if the key to be removed is currently the active key
        is_active_key = self._get_active_key_name() == rm_key

        # Delete the specified key
        self._delete_key_file(key_path)

        # If it was the default key, also delete the backup
        if rm_key == self.DEFAULT_KEY_NAME:
            backup_path = self.script_path.joinpath(f"{self.DEFAULT_KEY_NAME}.bak")
            if backup_path.is_file():
                self._delete_key_file(backup_path)

        # If the removed key was the active key, update settings.ini
        if is_active_key:
            self._blank_settings_file()
            print(f"Active key '{rm_key}' removed. Configuration reset")

    def _blank_settings_file(self) -> None:
        """Blanks out the settings.ini file."""
        with open(self.settings_path, "w") as configfile:
            configfile.write("")

    def _delete_key_file(self, key_path: Path) -> None:
        """Deletes a key file, handling read-only permissions."""
        try:
            # Ensure the file is writable before deleting.
            key_path.chmod(0o600)

            # Remove the key file.
            key_path.unlink()
            print(f"Key deleted: {key_path.name}")

        except Exception as e:
            print(f"Failed to delete key {key_path.name}: {e}")

    def _has_any_keys(self) -> bool:
        """Check if any .key files exist (excluding backups)"""
        key_files = list(self.script_path.glob("*.key"))
        actual_key_files = [f for f in key_files if not f.name.endswith(".bak")]
        return len(actual_key_files) > 0

    def _is_only_key_remaining(self, key_to_remove: str) -> bool:
        """Check if the specified key is the only .key file remaining"""
        key_files = list(self.script_path.glob("*.key"))
        # Filter out backup files (.key.bak)
        actual_key_files = [f for f in key_files if not f.name.endswith(".bak")]

        # Return True if there's only one key file and it matches the one being removed
        return len(actual_key_files) == 1 and actual_key_files[0].name == key_to_remove

    def _is_key_in_store(self, key: str) -> bool:
        """Check if the key is used as the default key"""
        if self._get_active_key_name() == key:
            print(
                f"[WARNING] Key '{key}' is currently active. Use -c to change key before operations"
            )
            return True
        return False
