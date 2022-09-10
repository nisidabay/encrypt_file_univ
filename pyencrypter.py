#!/usr/bin/python3

##############################################################################
# Author: Carlos Lacaci Moya
# Name: pyencrypter_univ.py
# Description: Interface to enc_dec_file.py
# Creation Date: vie 11 mar 2022 09:07:58 CET
# Modified Date: sáb 10 sep 2022 08:40:12 CEST
# Version: 1.1
# Dependencies: See requirements.txt

# Options:
# -e          encrypt <file>
# -d          decrypt <file>
# -c          change a key making it the default key
# -m          make a new key
# -r          remove a key
# -s          show active key
# -u          make a key undeletable
# --version   program version
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
    pyencrypter.py -u (make a key undeletable)

Options:
    -e          encrypt <file>
    -d          decrypt <file>
    -c          change a key making it the default key
    -m          make a new key
    -r          remove a key
    -s          show active key
    -u          make a key undeletable
    --version   program version
"""
from pathlib import Path
from docopt import docopt  #type: ignore
from enc_dec_file_univ import EncryptFile

if __name__ == "__main__":
    args = docopt(__doc__, version="pyencrypter v.1.1 - 2022")  #type: ignore
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
        print("Remove a key")
        encrypt.remove_key()

    if args["-s"]:
        print("Showing active key")
        encrypt.show_active_key()

    if args["-u"]:
        print("Making a key undeletable")
        encrypt.make_key_undeletable()
    else:
        print(f"Type: {Path(__file__).name} -h for help")
