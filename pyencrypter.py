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
    pyencrypter.py ([-e] <file> | [-d] <file> | [options])

    pyencrypter.py -e file.txt (output: file.enc)
    pyencrypter.py -d file.enc (output: file.dec)
    pyencrypter.py -c (change a key making it the default key)
    pyencrypter.py -m (make a new key)
    pyencrypter.py -r (remove a key)
    pyencrypter.py -s (show active key)
    pyencrypter.py -u (make a key read-only)

Options:
    -e          encrypt <file>
    -d          decrypt <file>
    -c          change a key making it the default key
    -m          make a new key
    -r          remove a key
    -s          show active key
    -u          make a key read-only
    --version   program version
"""
from pathlib import Path
from docopt import docopt
from enc_dec_file_univ import EncryptFile

if __name__ == "__main__":
    args = docopt(__doc__, version="pyencrypter v.1.2 - 2025")
    encrypt = EncryptFile()

    file = args["<file>"]
    if args["-e"]:
        print("Encrypting file")
        encrypt.encrypt(file)

    if args["-d"]:
        print("Decrypting file")
        encrypt.decrypt(file)

    if args["-c"]:
        print("Changing a key")
        encrypt.change_key()

    if args["-m"]:
        print("Making a new key")
        encrypt.make_new_key()

    if args["-r"]:
        print("Removing a key")
        encrypt.remove_key()

    if args["-s"]:
        print("Showing active key")
        encrypt.show_active_key()

    if args["-u"]:
        print("Making a key read-only")
        encrypt.make_key_readonly()
    else:
        print(f"Type: {Path(__file__).name} -h for help")
