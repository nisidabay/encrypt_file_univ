#!/usr/bin/env python3

##############################################################################
# Author: nisidabay
# Name: pyencrypter_univ.py
# Description: Interface to enc_dec_file.py
# Creation Date: vie 11 mar 2022 09:07:58 CET
# Modified Date: sáb 10 sep 2022 08:40:12 CEST
# Modified Date: Thu Nov 13 11:22:53 AM CET 2025
# Version: 1.2
# Dependencies: See requirements.txt
##############################################################################
"""
Usage:
    pyencrypter.py -e <file> [-p]
    pyencrypter.py -d <file> [-p]
    pyencrypter.py ( -c | -m | -r | -s | -u )

Options:
    -e                 Encrypt the specified file.
    -d                 Decrypt the specified file.
    -p, --password     Use password-based encryption/decryption.
    -c                 Change the active key used for encryption/decryption.
    -m                 Make a new, named encryption key.
    -r                 Remove a key.
    -s                 Show the currently active key.
    -u                 Make a specific key read-only.
    --version          Program version.
    -h, --help         Show this help message.
"""
from pathlib import Path
from docopt import docopt
from getpass import getpass
from enc_dec_file_univ import EncryptFile

if __name__ == "__main__":
    args = docopt(__doc__, version="pyencrypter v.2.0.0 - 2026")
    encrypt = EncryptFile()

    password = None
    if args["--password"]:
        password = getpass("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            exit(1)

    if args["-e"]:
        print("Encrypting file")
        encrypt.encrypt(args["<file>"], password=password)

    elif args["-d"]:
        print("Decrypting file")
        encrypt.decrypt(args["<file>"], password=password)

    elif args["-c"]:
        print("Changing a key")
        encrypt.change_key()

    elif args["-m"]:
        print("Making a new key")
        encrypt.make_new_key()

    elif args["-r"]:
        print("Removing a key")
        encrypt.remove_key()

    elif args["-s"]:
        print("Showing active key")
        encrypt.show_active_key()

    elif args["-u"]:
        print("Making a key read-only")
        encrypt.make_key_readonly()
