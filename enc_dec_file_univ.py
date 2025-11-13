#!/usr/bin/env python3

##############################################################################
# Author: Carlos Lacaci Moya
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
from helpers import BeautiPanel


@dataclass
class EncryptFile:
    """Encrypt/Decrypt file using Fernet"""

    script_path: Path = field(default_factory=lambda: Path(__file__).parent.absolute())
    settings_path: Path = field(init=False)
    DEFAULT_KEY_NAME: str = "default.key"

    def __post_init__(self) -> None:
        """Check if the settings file is valid and create it if not."""
        self.settings_path = self.script_path.joinpath("settings.ini")

        config = ConfigParser()
        files_read = config.read(self.settings_path)

        is_valid = False
        # The config file should be in the list of read files.
        # Note: config.read() returns a list of successfully read files.
        if str(self.settings_path) in files_read:
            try:
                # It's valid if we can read the key.
                config.get("settings", "key")
                is_valid = True
            except (NoSectionError, NoOptionError):
                is_valid = False

        if not is_valid:
            self._initialize_project()

    def _initialize_project(self) -> None:
        """Creates settings.ini, a default key, and its backup."""
        BeautiPanel.draw_panel(
            "yellow", "[!] No settings.ini found. Creating default configuration."
        )

        # Create default key
        key_path = self.script_path.joinpath(self.DEFAULT_KEY_NAME)
        if not key_path.is_file():
            BeautiPanel.draw_panel(
                "yellow", f"[!] {self.DEFAULT_KEY_NAME} not found. Generating a new key"
            )
            with open(key_path, "wb") as fk:
                fk.write(Fernet.generate_key())

        # Create settings.ini and set default key as default
        self._write_key_in_store(self.DEFAULT_KEY_NAME)

        # Backup default key
        backup_path = self.script_path.joinpath(f"{self.DEFAULT_KEY_NAME}.bak")
        if not backup_path.is_file():
            shutil.copy(key_path, backup_path)
            BeautiPanel.draw_panel(
                "green",
                f"[+] Making a backup of {self.DEFAULT_KEY_NAME}.bak",
                borderstyle="blue",
            )
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
        """Set the key to be read-only on Mac."""
        try:
            # Set the file permissions to read-only for the owner
            Path(key_path).chmod(0o400)
            BeautiPanel.draw_panel(
                "green",
                f"[+] Making the key read-only: {key_path}",
                borderstyle="blue",
            )
        except Exception as e:
            BeautiPanel.draw_panel(
                "red", f"[!] Could not make key read-only: {key_path}: {e}"
            )

    def _key_linux(self, key_path: str) -> None:
        """Set the key to be read-only on Linux."""
        try:
            # Set the file permissions to read-only for the owner
            Path(key_path).chmod(0o400)
            BeautiPanel.draw_panel(
                "green",
                f"[+] Making the key read-only: {key_path}",
                borderstyle="blue",
            )
        except Exception as e:
            BeautiPanel.draw_panel(
                "red", f"[!] Could not make key read-only: {key_path}: {e}"
            )

    def change_key(self) -> None:
        """Change and load new key"""
        self.show_active_key()
        new_key = input("Enter new key name: ")
        if not self.script_path.joinpath(new_key).is_file():
            BeautiPanel.draw_panel("yellow", f"[!] Key {new_key} not found")
            sys.exit(1)
        self._write_key_in_store(new_key)
        BeautiPanel.draw_panel("yellow", f"[!] Active key is: {new_key}")

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
            BeautiPanel.draw_panel(
                "red",
                f"[!] Critical error: Cannot read settings.ini. Please delete it and run again. Error: {e}",
            )
            sys.exit(1)

    def show_active_key(self) -> None:
        """Show active key"""
        active_key = self._get_active_key_name()
        BeautiPanel.draw_panel("yellow", f"[!] Active key is: {active_key}")

    def _load_key(self) -> Fernet:
        """Read and load the Personal key"""
        key_name = self._get_active_key_name()
        key_path = self.script_path.joinpath(key_name)
        if not key_path.is_file():
            BeautiPanel.draw_panel(
                "yellow", f"[!] Key {key_name} does not exist. Change the key with -c"
            )
            sys.exit(1)
        with open(key_path, "rb") as fk:
            return Fernet(fk.read())

    def _file_exists(self, local_file: str) -> Path:
        """Check if the file to work on exists"""
        file_path = Path(local_file)
        if not file_path.exists():
            BeautiPanel.draw_panel(
                "yellow", "[!] File does not exist. Please check filename"
            )
            sys.exit(1)
        return file_path

    def make_new_key(self) -> None:
        """Create a new key"""
        new_key = input("Enter new key name: ")
        if not new_key.endswith(".key"):
            new_key += ".key"
        key_path = self.script_path.joinpath(new_key)
        if key_path.is_file():
            BeautiPanel.draw_panel("yellow", f"[!] Key {new_key} already exists")
            sys.exit(1)
        with open(key_path, "wb") as fk:
            fk.write(Fernet.generate_key())
            BeautiPanel.draw_panel(
                "green",
                f"[+] Created new key: {new_key}. Make it read-only with -u",
                borderstyle="blue",
            )

    def make_key_readonly(self) -> None:
        """Make a key read-only"""
        new_key = input("Enter the key name you want to make read-only: ")
        if not self.script_path.joinpath(new_key).is_file():
            BeautiPanel.draw_panel("yellow", f"[!] Key {new_key} not found")
            sys.exit(1)
        self._mk_key_readonly(new_key)

    def encrypt(self, local_file: str) -> None:
        """Encrypt the file"""
        file_path = self._file_exists(local_file)
        with open(file_path, "rb") as file_to_read:
            encrypted_file = self._load_key().encrypt(file_to_read.read())
            with open(f"{file_path.stem}.enc", "wb") as encoded_file:
                encoded_file.write(encrypted_file)
            BeautiPanel.draw_panel(
                "green",
                f"[+] File encrypted as {file_path.stem}.enc",
                borderstyle="blue",
            )

    def decrypt(self, local_file: str) -> None:
        """Decrypt the file"""
        file_path = self._file_exists(local_file)
        try:
            with open(file_path, "rb") as file_to_read:
                decrypted_file = self._load_key().decrypt(file_to_read.read())
                with open(f"{file_path.stem}.dec", "wb") as decoded_file:
                    decoded_file.write(decrypted_file)
        except InvalidToken:
            BeautiPanel.draw_panel(
                "yellow",
                "[!] Decrypting with wrong key. Have you changed the encryption key?",
            )
            sys.exit(1)
        BeautiPanel.draw_panel(
            "green", f"[+] File decrypted as {file_path.stem}.dec", borderstyle="blue"
        )
        file_path.unlink()

    def remove_key(self) -> None:
        """Remove selected key and its backup if it is the default key."""
        rm_key = input("Enter the key name to remove: ")

        key_path = self.script_path.joinpath(rm_key)
        if not key_path.is_file():
            BeautiPanel.draw_panel("yellow", f"[!] Key {rm_key} not found")
            sys.exit(1)

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
            BeautiPanel.draw_panel(
                "yellow",
                f"[!] The removed key ({rm_key}) was the active key. settings.ini has been reset. A new default key will be generated on next run.",
            )

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
            BeautiPanel.draw_panel(
                "green",
                f"[+] The key {key_path.name} has been deleted",
                borderstyle="blue",
            )

        except Exception as e:
            BeautiPanel.draw_panel(
                "red", f"[!] Error deleting key {key_path.name}: {e}"
            )

    def _is_key_in_store(self, key: str) -> bool:
        """Check if the key is used as the default key"""
        if self._get_active_key_name() == key:
            BeautiPanel.draw_panel(
                "yellow",
                f"[!] The key {key} is the default key. Choose a new key with -c before encrypt or decrypt",
            )
            return True
        return False
