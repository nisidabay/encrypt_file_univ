# pyencrypter
Encripyt/Decrypt files using Fernet


usage: pyencrypter.py [-h] [-V] (-d | -e) file

Encrypt/Decrypt a file

positional arguments:
  file           file to encrypt

options:
  -h, --help     show this help message and exit
  
  -V, --version  show program version number and exit
  
  -d, --decrypt  decrypt a file
  
  -e, --encrypt  encrypt a file

Encrypt a file with .enc extension. Decrypt a file with .dec extension

Notes
-----
Automatically generate a fernet.key file in the script directory and make it undeletable.
Works both on Linux and Mac.

Todo
----
To add the ability to import temporary keys from diffent users/projects for encode/decode specific files.
