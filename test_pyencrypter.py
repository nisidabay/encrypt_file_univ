import unittest
import os
import sys
import shutil
from unittest.mock import patch
from pathlib import Path
from io import StringIO

# Add the project directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from enc_dec_file_univ import EncryptFile
from configparser import ConfigParser, NoSectionError, NoOptionError


class TestPyEncrypter(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for testing
        self.original_cwd = Path.cwd()
        self.test_dir = self.original_cwd / "test_temp_dir"
        self.test_dir.mkdir(exist_ok=True)
        os.chdir(self.test_dir)

        # Capture stdout
        self.held_output = StringIO()
        self.stdout_patch = patch("sys.stdout", self.held_output)
        self.stdout_patch.start()

        # Ensure a clean state for each test
        self._cleanup_test_dir()

        # Initialize EncryptFile with the test directory
        self.encrypt_app = EncryptFile(script_path=self.test_dir)
        # Manually initialize the project as it's not done in EncryptFile's __post_init__
        self.encrypt_app._initialize_project()

    def tearDown(self):
        # Stop capturing stdout
        self.stdout_patch.stop()

        # Clean up the temporary directory
        os.chdir(self.original_cwd)
        self._cleanup_test_dir()
        self.test_dir.rmdir()

    def _cleanup_test_dir(self):
        if self.test_dir.exists():
            for item in self.test_dir.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)

    def _get_settings_key(self):
        config = ConfigParser()
        config.read("settings.ini")
        try:
            return config.get("settings", "key")
        except (NoSectionError, NoOptionError):
            return None

    def test_initial_setup(self):
        # Simulate first run: no settings.ini, no default.key
        # EncryptFile is already initialized in setUp, so it should have created the defaults

        self.assertTrue(Path("settings.ini").is_file())
        self.assertTrue(Path(self.encrypt_app.DEFAULT_KEY_NAME).is_file())
        self.assertTrue(Path(f"{self.encrypt_app.DEFAULT_KEY_NAME}.bak").is_file())
        self.assertEqual(self._get_settings_key(), self.encrypt_app.DEFAULT_KEY_NAME)
        output = self.held_output.getvalue()
        self.assertIn("[INFO] Initializing project with default configuration", output)
        self.assertIn(
            f"[INFO] Generating new encryption key: {self.encrypt_app.DEFAULT_KEY_NAME}",
            output,
        )
        self.assertIn(
            f"[INFO] Created backup: {self.encrypt_app.DEFAULT_KEY_NAME}.bak", output
        )
        self.assertIn(f"Key secured: {self.encrypt_app.DEFAULT_KEY_NAME}.bak", output)
        self.assertIn(f"Key secured: {self.encrypt_app.DEFAULT_KEY_NAME}", output)

    @patch("builtins.input", side_effect=["new_test.key"])
    def test_make_new_key(self, mock_input):
        self.encrypt_app.make_new_key()
        self.assertTrue(Path("new_test.key").is_file())
        self.assertIn("Key created: new_test.key", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["new_active.key"])
    def test_change_key(self, mock_input):
        # Create a new key first
        with patch("builtins.input", side_effect=["new_active.key"]):
            self.encrypt_app.make_new_key()
        # Clear output from previous operation
        self.held_output.truncate(0)
        self.held_output.seek(0)

        self.encrypt_app.change_key()
        self.assertEqual(self._get_settings_key(), "new_active.key")
        self.assertIn("Active key: new_active.key", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["test_readonly.key"])
    def test_make_key_readonly(self, mock_input):
        # Create a key first
        with patch("builtins.input", side_effect=["test_readonly.key"]):
            self.encrypt_app.make_new_key()
        # Clear output from previous operation
        self.held_output.truncate(0)
        self.held_output.seek(0)

        key_path = Path("test_readonly.key")
        self.encrypt_app.make_key_readonly()
        # Verify permissions (read-only for owner)
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o400)
        self.assertIn(f"Key secured: {key_path.name}", self.held_output.getvalue())

    @patch("builtins.input", side_effect=[f"{EncryptFile.DEFAULT_KEY_NAME}", "yes"])
    def test_remove_default_key(self, mock_input):
        # Clear output from initial setup
        self.held_output.truncate(0)
        self.held_output.seek(0)

        self.encrypt_app.remove_key()
        self.assertFalse(Path(self.encrypt_app.DEFAULT_KEY_NAME).is_file())
        self.assertFalse(Path(f"{self.encrypt_app.DEFAULT_KEY_NAME}.bak").is_file())
        output = self.held_output.getvalue()
        self.assertIn(f"Key deleted: {self.encrypt_app.DEFAULT_KEY_NAME}", output)
        self.assertIn(f"Key deleted: {self.encrypt_app.DEFAULT_KEY_NAME}.bak", output)
        self.assertIn(
            f"Active key '{self.encrypt_app.DEFAULT_KEY_NAME}' removed. Configuration reset",
            output,
        )
        self.assertEqual(Path("settings.ini").read_text(), "")

    @patch("builtins.input", side_effect=["temp_file.txt", "temp_file.enc"])
    def test_encrypt_decrypt_file(self, mock_input):
        # Clear output from initial setup
        self.held_output.truncate(0)
        self.held_output.seek(0)

        # Create a test file
        test_content = "This is a secret message."
        Path("temp_file.txt").write_text(test_content)

        # Encrypt
        self.encrypt_app.encrypt("temp_file.txt")
        self.assertTrue(Path("temp_file.enc").is_file())
        self.assertIn("File encrypted: temp_file.enc", self.held_output.getvalue())

        # Clear output for decrypt operation
        self.held_output.truncate(0)
        self.held_output.seek(0)

        # Decrypt
        self.encrypt_app.decrypt("temp_file.enc")
        self.assertTrue(Path("temp_file.dec").is_file())
        self.assertEqual(Path("temp_file.dec").read_text(), test_content)
        self.assertIn("File decrypted: temp_file.dec", self.held_output.getvalue())
        self.assertFalse(
            Path("temp_file.enc").is_file()
        )  # Original encrypted file should be removed

    @patch("builtins.input", side_effect=["non_existent.key"])
    def test_remove_non_existent_key(self, mock_input):
        # Clear output from initial setup
        self.held_output.truncate(0)
        self.held_output.seek(0)

        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.remove_key()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Key 'non_existent.key' not found", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["non_existent.txt"])
    def test_encrypt_non_existent_file(self, mock_input):
        # Clear output from initial setup
        self.held_output.truncate(0)
        self.held_output.seek(0)

        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.encrypt("non_existent.txt")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("File 'non_existent.txt' not found", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["non_existent.enc"])
    def test_decrypt_non_existent_file(self, mock_input):
        # Clear output from initial setup
        self.held_output.truncate(0)
        self.held_output.seek(0)

        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("non_existent.enc")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("File 'non_existent.enc' not found", self.held_output.getvalue())

    def test_decrypt_wrong_key(self):
        # Clear output from initial setup
        self.held_output.truncate(0)
        self.held_output.seek(0)

        # Create a test file
        test_content = "This is a secret message."
        Path("temp_file.txt").write_text(test_content)

        # Encrypt with default.key
        self.encrypt_app.encrypt("temp_file.txt")

        # Create a new key and make it active
        with patch("builtins.input", side_effect=["wrong.key"]):
            self.encrypt_app.make_new_key()
        # Clear output from make_new_key
        self.held_output.truncate(0)
        self.held_output.seek(0)

        with patch("builtins.input", side_effect=["wrong.key"]):
            self.encrypt_app.change_key()
        # Clear output from change_key
        self.held_output.truncate(0)
        self.held_output.seek(0)

        # Try to decrypt with wrong.key
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("temp_file.enc")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Invalid decryption key. File may have been encrypted with a different key",
            self.held_output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()

