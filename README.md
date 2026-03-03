# PyEncrypter

A simple and secure command-line tool for file encryption and decryption using
either local key files or a password.

---

## Description

PyEncrypter provides a straightforward way to secure your sensitive files
directly from the terminal. It supports both key-file and password-based
encryption using the robust `cryptography` library to perform AES-256-GCM
encryption, ensuring your data is protected and authenticated.

This tool is designed for users who need a quick, reliable, and scriptable
method for local file encryption without the complexity of managing a
full-blown security suite.

### Key Features

*   **Strong, Modern Encryption:** Utilizes AES-256-GCM, an authenticated
    encryption mode that provides confidentiality and integrity.
*   **Dual-Mode Operation:** Choose between secure password-based encryption (which
    derives a key using PBKDF2) or a traditional key-file method.
*   **Large File Support:** Encrypts and decrypts files of any size efficiently
    thanks to a streaming implementation that reads files in chunks.
*   **Standard-Based Key Storage:** When using key files, all keys and settings
    are neatly stored in `~/.config/pyencrypter`, following system standards.
*   **Full Key Management:** Easily create, switch between, and remove
    encryption key files.
*   **Command-Line Interface:** A simple and intuitive CLI makes all operations
    a breeze.

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
    ```

3.  **Install the required dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Verify the installation:**
    Upon first run, the script will automatically create a configuration
    directory at `~/.config/pyencrypter` with a default key.
    ```sh
    ./pyencrypter.py --version
    ```
    Expected output: `pyencrypter v.2.0.0 - 2026`

## Quick Start

### Option 1: Password-Based (Recommended)

This is the most secure and convenient method.

1.  **Create a sample file:**
    ```sh
    echo "This is a secret message." > my_secrets.txt
    ```

2.  **Encrypt the file with a password:**
    Use the `-p` flag. You will be securely prompted for a password.
    ```sh
    ./pyencrypter.py -e my_secrets.txt -p
    ```
    Output:
    ```
    Enter password: ****
    Encrypting file
    File encrypted: my_secrets.enc
    ```

    ```sh
    ./pyencrypter.py -d my_secrets.enc -p
    ```
    Output:
    ```
    Enter password: ****
    Decrypting file
    File decrypted: my_secrets.dec
    ```
    *Note: Decryption leaves the original `.enc` file intact.*

### Option 2: Key-File Based

This method uses key files stored in `~/.config/pyencrypter`.

1.  **Encrypt the file:**
    The script will use the default `default.key`.
    ```sh
    ./pyencrypter.py -e my_secrets.txt
    ```

2.  **Decrypt the file:**
    ```sh
    ./pyencrypter.py -d my_secrets.enc
    ```
    *Note: Decryption leaves the original `.enc` file intact.*

## Command-Line API

```
Usage:
    pyencrypter.py -e <file> [-p]
    pyencrypter.py -d <file> [-p]
    pyencrypter.py ( -c | -m | -r | -s | -u )

Options:
    -e <file>          Encrypt the specified file.
    -d <file>          Decrypt the specified file.
    -p, --password     Use password-based encryption/decryption.
    -c                 Change the active key used for encryption/decryption.
    -m                 Make a new, named encryption key.
    -r                 Remove a key.
    -s                 Show the currently active key.
    -u                 Make a specific key read-only.
    --version          Program version.
    -h, --help         Show this help message.
```

### Key Management Examples

Key management commands only apply when you are **not** using the `-p` flag.

*   **Create a new key named `project_x.key`:**
    ```sh
    ./pyencrypter.py -m
    # Enter new key name: project_x
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

For key-file mode, the active encryption key is configured via the `settings.ini`
file, which is located in `~/.config/pyencrypter/` (or `$XDG_CONFIG_HOME/pyencrypter/` if set).

**File:** `~/.config/pyencrypter/settings.ini`
```ini
[settings]
key = default.key
```
*   `key`: The filename of the key within the config directory that will be
    used for all key-based encryption and decryption operations.

## Development

### Testing

To run the full test suite and verify all functionality:
```sh
python3 ./test_pyencrypter.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.

## Author
*   **nisidabay** 

## Acknowledgments

*   The developers of the [cryptography.io](https://cryptography.io/en/latest/)
    library for providing powerful and easy-to-use cryptographic primitives.
