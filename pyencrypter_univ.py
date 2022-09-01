#!/usr/bin/python3

##############################################################################
# Author: Carlos Lacaci Moya
# Name: pyencrypter_univ.py
# Description: Interface to enc_dec_file.py
# Date: vie 11 mar 2022 09:07:58 CET
# Version: 1.0.0
# Dependencies: EncryptFile class

# Options
# -d decrypt file
# -e encrypt file
# -h show help
# -u make key undeletable
# -V program version
##############################################################################

import argparse
from dataclasses import dataclass, field
from typing import Any
from enc_dec_file_univ import EncryptFile


@dataclass
class Parser:
    """Get options from cmd-line arguments """

    args: Any = field(init=False)
    Encryption: Any = EncryptFile()

    def __post_init__(self) -> None:
        """Declare and get the cli arguments"""

        self._create_parser()

    def _create_parser(self) -> Any:
        """Create parser object"""

        self.parser = argparse.ArgumentParser(
            prog="pyencrypter.py",
            description="Encrypt/Decrypt a file",
            epilog="""Encrypt a file with .enc extension. 
            Decrypt a file with .dec extension""")

        self.parser.add_argument(
            "-V",
            "--version",
            action="version",
            version="pyencrypter.py 1.0.0 - Carlos Lacaci Moya 2022")

        self.mutually_exclusive = self.parser.add_mutually_exclusive_group(
            required=True)
        self.mutually_exclusive.add_argument("-d",
                                             "--decrypt",
                                             help="decrypt a file",
                                             action="store_const",
                                             const=self.Encryption.decrypt,
                                             dest="cmd")

        self.mutually_exclusive.add_argument("-e",
                                             "--encrypt",
                                             help="encrypt a file",
                                             action="store_const",
                                             const=self.Encryption.encrypt,
                                             dest="cmd")

        self.parser.add_argument("file", help="file to encrypt")

        self.args = self.parser.parse_args()
        return self.args


if __name__ == "__main__":
    parser = Parser()
    if parser.args.__dict__['cmd'] is None:
        print("[!] Type 'pyencrypter.py -h' for help")
    else:
        file = parser.args.file
        parser.args.cmd(file)
