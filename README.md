# Pyencrypter

#### Encrypt/Decrypt a file using Fernet symmetric encryption.

##### Usage:

    pyencrypter.py ([-e] <file> | [-d] <file> | [options]) 
    
    pyencrypter.py -e file.txt (output: file.enc)
    pyencrypter.py -d file.enc (output: file.dec)
    pyencrypter.py -c (change a key)
    pyencrypter.py -m (make a new key)
    pyencrypter.py -r (remove a key)
    pyencrypter.py -s (show active key)
    pyencrypter.py -u (make a key undeleteable)

##### Options:

```
    -e          encrypt <file>
    -d          decrypt <file>
    -c          change a key
    -m          make a new key
    -r          remove a key
    -s 			show active key
    -u			make a key undeletable
    --version	program version
```

##### Features

- Automatically generate a "**fernet.key**" in the script directory and a backup: "**fernet.key.bak**" and make them both undeletable. 
- Create keys and change them as needed as disposable keys.
- Make keys undeletables by choosing the [-u] option.
- Remove keys except the "fernet.key" wich will have to be done manually.
- Once a file has been decrypted don't forget to change the "*dec" extension with the original one.
- The encrypted file with "enc" will be deleted after decryption.
- Tested on Linux and Mac.

**Caveats**

- It is recommended that all the keys you make have the ".key" extension although if omitted the extension will be added by default.
- Once you made a key undeletable with the [-u] flag it can be only deleted with the [-r] flag. 

To delete the "fernet.key" and the "fernet.key.bak":

- On Linux type:`sudo chattr -i fernet*; rm fernet*`
- On Mac type: `sudo chflags nouchg fernet\*; rm fernet*`


**Requirements**

- cryptography==37.0.4

- docopt==0.6.2
- python-decouple==3.6
- rich==12.5.1


**End note**

This script was made as a personal project based on my needs.

If you want to learn where the idea came from visit the link.

https://cryptography.io/en/latest/fernet/
