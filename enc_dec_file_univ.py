#!/usr/bin/python3

##############################################################################
# Author: Carlos Lacaci Moya
# Name: enc_dec_file_univ.py
# Description: Encrypt and decrypt a file using Fernet encryption
# Creation Date: vie 11 mar 2022 09:07:58 CET
# Modified Date: sáb 10 sep 2022 08:38:23 CEST
# Version: 1.1
# Dependencies: See requirements.txt
##############################################################################
import sys
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from decouple import config  #type: ignore
from typing import Any
from cryptography.fernet import Fernet, InvalidToken
from helpers import BeautiPanel, RunCommand


@dataclass
class EncryptFile:
    """Encrypt/Decrypt file using Fernet"""

    process: Any = field(default=RunCommand(), init=False)
    script_path = Path(__file__).parent.absolute()

    def __post_init__(self) -> None:
        """Check if the default key exists and make it undeletable if not 
           done already"""

        self.my_private_key = self._check_the_key()
        self._mk_key_undeletable()
        self._mk_backup()

    def _check_the_key(self) -> Path:
        """Return the key or create a new Key"""

        if not self.script_path.joinpath("fernet.key").is_file():
            BeautiPanel.draw_panel(
                "yellow", "[!] fernet.key not found. Generating a new key")

            with open("fernet.key", "wb") as fk:
                fk.write(Fernet.generate_key())

        return self.script_path.joinpath("fernet.key")

    def _mk_backup(self) -> None:
        """ Make a backup copy of the key """
        if not self.script_path.joinpath("fernet.key.bak").is_file():

            shutil.copy("fernet.key", "fernet.key.bak")
            BeautiPanel.draw_panel("green",
                                   "[+] Making a backup of fernet.key.bak",
                                   borderstyle="blue")

            self._mk_key_undeletable("fernet.key.bak")

    def _mk_key_undeletable(self, key: str = "") -> None:
        """Make the key undeletable if not already set"""

        if sys.platform == "darwin":
            self._key_mac(key)

        elif sys.platform == "linux":

            # Check for the inmutable attribute
            self._key_linux(key)

    def _key_mac(self, key: str = ""):
        """Set the undetable flags for Mac"""

        # If not key provided is the "fernet.key"
        if key == "":
            check_flag = f"ls -lO {self.my_private_key} | sed -n '/uchg/p' | wc -l"
            set_flag = f"chflags uchg {self.my_private_key}"

        # This is the key you want to protect
        else:

            check_flag = f"ls -lO {key} | sed -n '/uchg/p' | wc -l"
            set_flag = f"chflags uchg {key}"

        output = RunCommand.run(check_flag)

        # The inmutable flag is not set on the fernet.key
        if int(output[0]) != 1 and key == "":
            set_flag = f"chflags uchg {self.my_private_key}"
            # BeautiPanel.draw_panel("yellow",
            # "[!] Found unprotected Fernet key")

            RunCommand.run(set_flag)
            BeautiPanel.draw_panel("green",
                                   "[+] Making the Fernet key undeletable",
                                   borderstyle="blue")
        # The inmutable flag is not set on the key
        elif int(output[0]) != 1 and key != "":
            set_flag = f"chflags uchg {key}"
            RunCommand.run(set_flag)
            BeautiPanel.draw_panel("green",
                                   f"[+] Making the {[key]} undeletable",
                                   borderstyle="blue")

    def _key_linux(self, key: str = ""):
        """Set the undeletable flags for Linux"""

        # If not key provided is the "fernet.key"
        if key == "":
            # check if the lsattr is set
            command = f"lsattr {self.my_private_key} | sed -n '/-i/p' | wc -l"
        # This is the key you want to protect
        else:
            command = f"lsattr {key} | sed -n '/-i/p' | wc -l"

        output = RunCommand.run(command)

        # The inmutable flag is not set on the fernet.key
        if int(output[0]) != 1 and key == "":
            command = f"sudo chattr +i {self.my_private_key}"
            # BeautiPanel.draw_panel("yellow",
            # "[!] Found unprotected Fernet key")
            RunCommand.run(command)
            BeautiPanel.draw_panel("green",
                                   "[+] Making the Fernet key undeletable",
                                   borderstyle="blue")

        # The inmutable flag is nor set on the key
        elif int(output[0]) != 1 and key != "":
            command = f"sudo chattr +i {key}"
            RunCommand.run(command)
            BeautiPanel.draw_panel("green",
                                   f"[+] Making the {[key]} undeletable",
                                   borderstyle="blue")

    def change_key(self) -> None:
        """ Change and load new key"""

        self.show_active_key()
        new_key = input("Enter new key name: ")

        if not self.script_path.joinpath(new_key).is_file():
            BeautiPanel.draw_panel("yellow", f"[!] {[new_key]} not found")
            sys.exit(1)
        else:
            self._write_key_in_store(new_key)
            BeautiPanel.draw_panel("yellow", f"[!] Active key is: {[new_key]}")
            sys.exit(0)

    def _write_key_in_store(self, key: str) -> None:
        """ Write the key in settings.ini """

        if not self.script_path.joinpath("settings.ini").is_file():
            BeautiPanel.draw_panel("yellow", "[!] Missing [settings.ini] file")
            sys.exit(1)
        else:
            with open("settings.ini", "w") as store:
                store.write("[settings]")
                store.write("\n")
                store.write(f"key={key}")

    def show_active_key(self) -> None:
        """ show active key """

        self.key = config('key')
        BeautiPanel.draw_panel("yellow", f"[!] Active key is: {[self.key]}")
        # sys.exit(0)

    def _load_key(self) -> Any:
        """Read and load the Personal key"""

        # If the key has changed, used this one instead
        self.key = config('key')

        if not self.script_path.joinpath(f"{self.key}").is_file():
            BeautiPanel.draw_panel(
                "yellow",
                f"[!] {[self.key]} does not exist. Change the key to use")
            sys.exit(1)

        path_new_key = self.script_path.joinpath(f"{self.key}")
        self.my_private_key = path_new_key

        with open(self.my_private_key, "rb") as fk:
            _key = fk.read()
            load_key = Fernet(_key)

        self.show_active_key()

        return load_key

    def _file_exists(self, local_file: str) -> Path:
        """Check if the file to work on exists"""

        _file_path = Path().joinpath(local_file)

        if not _file_path.exists():
            BeautiPanel.draw_panel(
                "yellow", "[!] File does not exist. Please check filename")
            sys.exit(1)

        return _file_path

    def make_new_key(self) -> None:
        """ Create a new key """

        new_key = input("Enter new key name: ")

        # Add ".key" extension to the key
        if not new_key.endswith(".key"):
            new_key += ".key"

        # FERNET.KEY CANNOT BE CREATED MANUALLY
        if new_key == "fernet.key" and self.script_path.joinpath(
                new_key).is_file():

            BeautiPanel.draw_panel(
                "yellow",
                f"[!] The {[new_key]} already exist and cannot be created manually"
            )
            sys.exit(1)

        if not new_key.endswith(".key"):
            new_key += ".key"

        with open(new_key, "wb") as fk:
            fk.write(Fernet.generate_key())
            BeautiPanel.draw_panel(
                "green",
                f"[+] Created new key: {[new_key]}. Make it undeletable with -u",
                borderstyle="blue")
        sys.exit(0)

    def make_key_undeletable(self) -> None:
        new_key = input("Enter the key name you want to protect: ")
        if not self.script_path.joinpath(new_key).is_file():
            BeautiPanel.draw_panel("yellow", f"[!] {[new_key]} not found")
            sys.exit(1)
        else:
            self._mk_key_undeletable(new_key)
            sys.exit(0)

    def encrypt(self, local_file: str) -> None:
        """Encrypt the file"""

        _file = self._file_exists(local_file)
        _file_name = _file.stem

        with open(_file, "rb") as file_to_read:
            encrypted_file = self._load_key().encrypt(file_to_read.read())
            with open(f"{_file_name}.enc", "wb") as encoded_file:
                encoded_file.write(encrypted_file)

            BeautiPanel.draw_panel("green",
                                   f"[+] File encrypted as {_file_name}.enc",
                                   borderstyle="blue")

    def decrypt(self, local_file: str) -> None:
        """ Decrypt the file """

        _file = self._file_exists(local_file)
        _file_name = _file.stem

        try:
            with open(_file, "rb") as file_to_read:
                decrypted_file = self._load_key().decrypt(file_to_read.read())
                with open(f"{_file_name }.dec", "wb") as decoded_file:
                    decoded_file.write(decrypted_file)
        except InvalidToken:
            BeautiPanel.draw_panel(
                "yellow",
                "[!] Decrypting with wrong key. Have you changed the encryption key?"
            )
            sys.exit(1)

        BeautiPanel.draw_panel("green",
                               f"[+] File decrypted as {_file_name}.dec]",
                               borderstyle="blue")

        # Once the file is decrypted delete the encrypted one
        Path().joinpath(f"{_file_name}.enc").unlink()

    def remove_key(self) -> None:
        """ Remove selected key"""

        if sys.platform == "darwin":
            self._rm_mac()

        elif sys.platform == "linux":

            # Check for the inmutable attribute
            self._rm_linux()

    def _rm_linux(self) -> None:
        """Remove the given key"""

        rm_key = input("Enter the key name to remove: ")
        # Cannot remove the fernet.key
        if rm_key == "fernet.key":
            BeautiPanel.draw_panel(
                "yellow",
                f"[!] Removing the {[rm_key]} and its backup has to be done manually"
            )
            sys.exit(1)

        if not self.script_path.joinpath(rm_key).is_file():
            BeautiPanel.draw_panel("yellow", f"[!] Key {[rm_key]} not found")
            sys.exit(1)

        # check if the lsattr is set
        command = f"lsattr {rm_key} | sed -n '/-i/p' | wc -l"

        output = RunCommand.run(command)

        # Is the active key?
        self._is_key_in_store(rm_key)

        # The inmutable flag is not set
        if int(output[0]) != 1:
            command = f"rm -f {rm_key}"
            RunCommand.run(command)
            BeautiPanel.draw_panel("green",
                                   f"[+] The key {[rm_key]} has been deleted",
                                   borderstyle="blue")
            sys.exit(0)

        # The inmutable flag is set
        elif int(output[0]) == 1:
            command = f"sudo chattr -i {rm_key}"
            RunCommand.run(command)

            print("Deleting the key")
            command = f"rm -f {rm_key}"
            RunCommand.run(command)
            BeautiPanel.draw_panel("green",
                                   f"[+] The key {[rm_key]} has been deleted",
                                   borderstyle="blue")

            sys.exit(0)

    def _rm_mac(self) -> None:
        """Remove the given key"""

        rm_key = input("Enter the key name to remove: ")
        # Cannot remove the fernet.key
        if rm_key == "fernet.key":
            BeautiPanel.draw_panel(
                "yellow",
                f"[!] Removing the {[rm_key]} and its backup has to be done manually"
            )
            sys.exit(1)

        if not self.script_path.joinpath(rm_key).is_file():
            BeautiPanel.draw_panel("yellow", f"[!] Key {[rm_key]} not found")
            sys.exit(1)

        check_flag = f"ls -lO {rm_key} | sed -n '/uchg/p' | wc -l"
        clear_flag = f"chflags nouchg {rm_key}"

        output = RunCommand.run(check_flag)

        # Is the active key?
        self._is_key_in_store(rm_key)

        # The inmutable flag is not set
        if int(output[0]) != 1:
            command = f"rm -f {rm_key}"
            RunCommand.run(command)
            BeautiPanel.draw_panel("green",
                                   f"[+] The key {[rm_key]} has been deleted")
            sys.exit(0)

        # The inmutable flag is set
        elif int(output[0]) == 1:
            RunCommand.run(clear_flag)

            print("Deleting the key")
            command = f"rm -f {rm_key}"
            RunCommand.run(command)
            BeautiPanel.draw_panel("green",
                                   f"[+] The key {[rm_key]} has been deleted",
                                   borderstyle="blue")

            sys.exit(0)

    def _is_key_in_store(self, key: str) -> bool:
        """ Returns if the key is used as default key """

        found = False
        if config('key') == key:
            found = True
            BeautiPanel.draw_panel(
                "yellow",
                f"[!] The {[key]} is the default key. Choose a new key with -c before encrypt or decrypt"
            )
        return found
