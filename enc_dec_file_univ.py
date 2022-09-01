#!/usr/bin/python3

##############################################################################
# Author: Carlos Lacaci Moya
# Name: enc_dec_file_univ.py
# Description: Encrypt and decrypt a file using Fernet encryption
# Date: vie 11 mar 2022 09:07:58 CET
# Dependencies: See below
##############################################################################
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any
from cryptography.fernet import Fernet, InvalidToken
from helpers import BeautiPanel


@dataclass
class EncryptFile:
    """Encrypt/Decrypt file using Fernet"""

    _generate_key: Any = field(default=Fernet.generate_key(), init=False)
    script_path = Path(__file__).parent.absolute()

    def __post_init__(self) -> None:
        """Check if the key exists and make it undeletable if not 
           done already"""

        self.my_private_key = self._check_the_key()
        self.mk_key_undeletable()

    def _check_the_key(self) -> Path:
        """Return or create a new Key"""

        if not self.script_path.joinpath("fernet.key").is_file():
            BeautiPanel.draw_panel("yellow",
                                   "[!] Key not found. Generating a new key")

            with open("fernet.key", "wb") as fk:
                fk.write(self._generate_key)

        return self.script_path.joinpath("fernet.key")

    def mk_key_undeletable(self) -> None:
        """Make the key undeletable if not already set"""

        if sys.platform == "darwin":
            self._key_mac()

        elif sys.platform == "linux":

            # Check for the inmutable attribute
            self._key_linux()

    def _key_mac(self):
        """Set the undeletable flags for Mac"""

        check_flag = f"ls -lO {self.my_private_key} | sed -n '/uchg/p' | wc -l"
        set_flag = f"chflags uchg {self.my_private_key}"

        # check if uchg flags are set
        process = subprocess.Popen(check_flag,
                                   stdout=subprocess.PIPE,
                                   universal_newlines=True,
                                   shell=True)
        process.wait()
        output = process.communicate()
        # The inmutable flag is set
        if int(output[0]) != 1:

            process = subprocess.Popen(set_flag,
                                       stdout=subprocess.PIPE,
                                       universal_newlines=True,
                                       shell=True)
            BeautiPanel.draw_panel("yellow",
                                   "[!] Making the Fernet key undeletable")

    def _key_linux(self):

        # check if the lsattr is set
        command = f"lsattr {self.my_private_key} | sed -n '/-i/p' | wc -l"

        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   universal_newlines=True,
                                   shell=True)
        process.wait()
        output = process.communicate()

        # The inmutable flag is not set
        if int(output[0]) != 1:
            BeautiPanel.draw_panel("yellow",
                                   "[!] Making the Fernet key undeletable")
            command = f"sudo chattr +i {self.my_private_key}"
            process = subprocess.Popen(command,
                                       stdout=subprocess.PIPE,
                                       universal_newlines=True,
                                       shell=True)

            process.wait()

    def _load_key(self) -> Any:
        """Read and load the key"""

        # key = self.script_path.joinpath("fernet.key")
        with open(self.my_private_key, "rb") as fk:
            _key = fk.read()

        load_key = Fernet(_key)

        return load_key

    def _file_exists(self, local_file: str) -> Path:
        """Check if the file to work on exists"""

        _file_path = Path().joinpath(local_file)

        if not _file_path.exists():
            BeautiPanel.draw_panel(
                "yellow", "[!] File does not exist. Please check filename")
            sys.exit(1)

        return _file_path

    def encrypt(self, local_file: str) -> None:
        """Encrypt the file"""

        _file = self._file_exists(local_file)
        _file_name = _file.stem

        with open(_file, "rb") as file_to_read:
            encrypted_file = self._load_key().encrypt(file_to_read.read())
            with open(f"{_file_name}.enc", "wb") as encoded_file:
                encoded_file.write(encrypted_file)

            BeautiPanel.draw_panel("green",
                                   f"[+] File encrypted as: {_file_name}.enc",
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
                "[!] Decoding with wrong key. Have you changed the encryption key?"
            )
            sys.exit(1)

        BeautiPanel.draw_panel("green",
                               f"[+] File decrypted as: {_file_name}.dec",
                               borderstyle="blue")

        # Once the file is decrypted delete the encrypted one
        Path().joinpath(f"{_file_name}.enc").unlink()
