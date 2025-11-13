# PyEncrypter

A simple and secure command-line tool for file encryption and decryption using
symmetric keys.

---

## Description

PyEncrypter provides a straightforward way to secure your sensitive files
directly from the terminal. It uses the robust Fernet implementation from the
`cryptography` library to perform AES-128 encryption, ensuring your data is
protected.

This tool was designed for users who need a quick, reliable, and scriptable
method for local file encryption without the complexity of managing a
full-blown security suite.

### Key Features

*   **Strong Encryption:** Utilizes Fernet's high-level symmetric encryption
(AES-128 in CBC mode with PKCS7 padding).
*   **Full Key Management:** Easily create, switch between, and remove
encryption keys.
*   **Command-Line Interface:** A simple and intuitive CLI makes encrypting and
decrypting files a breeze.
*   **Key Protection:** A unique feature that attempts to protect key files
from accidental deletion by setting them as read-only.

## Installation

### Prerequisites

*   Python 3.8 or newer
*   `pip` (Python package installer)


### Steps

1.  **Clone the repository:**
    ```sh
    gh repo clone nisidabay/encrypt_file_univ
    cd encrypt_file_univ
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```sh
    python3 -m venv .venv
    source .venv/bin/activate
    # On Windows, use: .venv\Scripts\activate
    ```

3.  **Install the required dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Verify the installation:**
    Upon first run, the script will automatically generate a default
    `default.key` and a `settings.ini` file. You can verify that the script is
    executable by checking its version: 
    ```sh
    ./pyencrypter.py --version
    ```
    Expected output: `pyencrypter v.1.2 - 2025`

## Quick Start

Here’s a minimal working example of how to encrypt and decrypt a file.

1.  **Create a sample file:**
    ```sh
    echo "This is a secret message." > my_secrets.txt
    ```

2.  **Encrypt the file:**
    The script will use the default `default.key` to create an encrypted version of your file named `my_secrets.enc`.
    ```sh
    ./pyencrypter.py -e my_secrets.txt
    ```
    Output:
    ```
    Encrypting file
    [+] File encrypted as my_secrets.enc
    ```

3.  **Decrypt the file:**
    This will decrypt `my_secrets.enc` into `my_secrets.dec` and remove the original `.enc` file.
    ```sh
    ./pyencrypter.py -d my_secrets.enc
    ```
    Output:
    ```
    Decrypting file
    [+] File decrypted as my_secrets.dec
    ```

4.  **Verify the content:**
    ```sh
    cat my_secrets.dec
    ```
    Output: `This is a secret message.`

## Command-Line API

The script is controlled via command-line arguments.

```
Usage:
    pyencrypter.py ([-e] <file> | [-d] <file> | [options])

Options:
    -e <file>   Encrypt the specified file.
    -d <file>   Decrypt the specified file.
    -c          Change the active key used for encryption/decryption.
    -m          Make a new, named encryption key.
    -r          Remove a key.
    -s          Show the currently active key.
    -u          Make a specific key read-only.
    --version   Show the program version.
    -h, --help  Show this help message.
```

### Key Management Examples

*   **Create a new key named `project_x.key`:**
    ```sh
    ./pyencrypter.py -m
    # Enter new key name: project_x.key
    ```

*   **Change the active key to `project_x.key`:**
    ```sh
    ./pyencrypter.py -c
    # Enter new key name: project_x.key
    ```

*   **Show the currently active key:**
    ```sh
    ./pyencrypter.py -s
    ```

## Configuration

The active encryption key is configured via the `settings.ini` file, which is
created automatically.

**File:** `settings.ini`

```ini
[settings]
key = default.key
```

*   `key`: The filename of the key within the script's directory that will be
    used for all encryption and decryption operations. You can edit this file
    manually or use the `-c` option to change it safely.

## Development

### Setup

Follow the [Installation](#installation) steps to set up a development
environment. Using a virtual environment is highly recommended.

### Testing

To run the test suite and verify the project's functionality, navigate to the
project root and execute:

```sh
python3 -m unittest test_pyencrypter.py
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.

## Author
*   **nisidabay** 

## Acknowledgments

*   The developers of the [cryptography.io](https://cryptography.io/en/latest/)
    library for providing the powerful and easy-to-use Fernet module.
