# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-03

### Added
- **Password-Based Encryption:** Added a new mode to encrypt and decrypt files using a password. The script now securely prompts for a password when the `-p` or `--password` flag is used.
- **Large File Support (Streaming):** Re-implemented the encryption and decryption logic to use a streaming approach. The tool can now handle files of any size without consuming excessive memory.
- **Standard Configuration Directory:** All key files and settings are now stored in `~/.config/pyencrypter`, following system standards for user configuration.
- **Backward Compatibility:** The tool can now decrypt files that were encrypted with older, non-streaming versions.
- **Changelog:** Added this `CHANGELOG.md` file to track project changes.

### Changed
- **Upgraded Encryption Algorithm:** Switched from the high-level Fernet implementation to a lower-level AES-256-GCM cipher to support streaming and provide strong, authenticated encryption.
- **Key Derivation:** Password-based encryption uses PBKDF2 with 100,000 iterations to derive a strong encryption key from the user's password.
- **Updated `README.md`:** The main documentation has been completely rewritten to reflect all the new features and usage instructions.

- **Security - PBKDF2 Iterations:** Increased the PBKDF2 iterations for password derivation from 100,000 to 600,000 to align with current OWASP recommendations for better protection against brute-force attacks.
- **Safe Decryption:** The tool no longer destructively unlinks the original encrypted file upon successful decryption, leaving it intact for the user to decide whether to delete it.
- **XDG_CONFIG_HOME Support:** The application now properly respects the `$XDG_CONFIG_HOME` environment variable before falling back to `~/.config` for its configuration directory.

### Fixed
- Corrected a bug where removing the default key did not remove its associated backup file.
- Fixed various bugs in the test suite to ensure all features are correctly validated.

## [1.2.0] - 2025 (Previous Version)

- Initial version of the script with Fernet-based encryption.
- Basic key management features (create, change, remove keys).
- A unique feature to make key files read-only.
