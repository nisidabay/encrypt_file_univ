import unittest
import os
import sys
import shutil
import subprocess
from unittest.mock import patch
from pathlib import Path
from io import StringIO

# Add the project directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from enc_dec_file_univ import EncryptFile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from configparser import ConfigParser, NoSectionError, NoOptionError

# Get the absolute path to the script
SCRIPT_PATH = Path(__file__).parent.resolve() / "pyencrypter.py"

class TestPyEncrypter(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory to act as a fake home
        self.original_cwd = Path.cwd()
        self.test_home_dir = self.original_cwd / "test_temp_home"
        self.test_home_dir.mkdir(exist_ok=True)
        
        # This is where the script will think the config should go
        self.config_dir = self.test_home_dir / ".config" / "pyencrypter"

        # We also need a directory to run the tests from, to create files for encryption
        self.run_dir = self.original_cwd / "test_run_dir"
        self.run_dir.mkdir(exist_ok=True)
        os.chdir(self.run_dir)

        # Patch Path.home() and XDG_CONFIG_HOME to make the app use our fake home directory
        self.home_patch = patch("pathlib.Path.home", return_value=self.test_home_dir)
        self.home_patch.start()
        
        self.env_patch = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.test_home_dir / ".config")})
        self.env_patch.start()

        # Capture stdout
        self.held_output = StringIO()
        self.stdout_patch = patch("sys.stdout", self.held_output)
        self.stdout_patch.start()

        # Initialize EncryptFile. It will now use the patched home path.
        self.encrypt_app = EncryptFile()
        self.encrypt_app._initialize_project()

    def tearDown(self):
        # Stop patches
        self.stdout_patch.stop()
        self.env_patch.stop()
        self.home_patch.stop()

        # Clean up the temporary directories
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_home_dir, ignore_errors=True)
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _get_settings_key(self):
        config = ConfigParser()
        config.read(self.config_dir / "settings.ini")
        try:
            return config.get("settings", "key")
        except (NoSectionError, NoOptionError):
            return None

    def test_initial_setup(self):
        # Check that the config directory and default files were created in our fake home
        self.assertTrue(self.config_dir.is_dir())
        self.assertTrue((self.config_dir / "settings.ini").is_file())
        self.assertTrue((self.config_dir / self.encrypt_app.DEFAULT_KEY_NAME).is_file())
        self.assertTrue((self.config_dir / f"{self.encrypt_app.DEFAULT_KEY_NAME}.bak").is_file())
        self.assertEqual(self._get_settings_key(), self.encrypt_app.DEFAULT_KEY_NAME)
        output = self.held_output.getvalue()
        self.assertIn("[INFO] Initializing project with default configuration", output)

    @patch("builtins.input", side_effect=["new_test.key"])
    def test_make_new_key(self, mock_input):
        self.encrypt_app.make_new_key()
        self.assertTrue((self.config_dir / "new_test.key").is_file())
        self.assertIn("Key created: new_test.key", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["new_active.key"])
    def test_change_key(self, mock_input):
        # Create a new key first
        with patch("builtins.input", side_effect=["new_active.key"]):
            self.encrypt_app.make_new_key()
        self.held_output.truncate(0); self.held_output.seek(0) # Clear output

        self.encrypt_app.change_key()
        self.assertEqual(self._get_settings_key(), "new_active.key")
        self.assertIn("Active key: new_active.key", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["test_readonly.key"])
    def test_make_key_readonly(self, mock_input):
        with patch("builtins.input", side_effect=["test_readonly.key"]):
            self.encrypt_app.make_new_key()
        self.held_output.truncate(0); self.held_output.seek(0)

        key_path = self.config_dir / "test_readonly.key"
        self.encrypt_app.make_key_readonly()
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o400)
        self.assertIn(f"Key secured: {key_path.name}", self.held_output.getvalue())

    @patch("builtins.input", side_effect=[f"{EncryptFile.DEFAULT_KEY_NAME}", "yes"])
    def test_remove_default_key(self, mock_input):
        self.held_output.truncate(0); self.held_output.seek(0)

        self.encrypt_app.remove_key()
        self.assertFalse((self.config_dir / self.encrypt_app.DEFAULT_KEY_NAME).is_file())
        self.assertFalse((self.config_dir / f"{self.encrypt_app.DEFAULT_KEY_NAME}.bak").is_file())
        self.assertEqual((self.config_dir / "settings.ini").read_text(), "")

    def test_encrypt_decrypt_file(self):
        self.held_output.truncate(0); self.held_output.seek(0)
        
        test_content = b"This is a secret message."
        Path("temp_file.txt").write_bytes(test_content)

        self.encrypt_app.encrypt("temp_file.txt")
        self.assertTrue(Path("temp_file.enc").is_file())
        self.held_output.truncate(0); self.held_output.seek(0)

        self.encrypt_app.decrypt("temp_file.enc")
        self.assertTrue(Path("temp_file.dec").is_file())
        self.assertEqual(Path("temp_file.dec").read_bytes(), test_content)
        self.assertTrue(Path("temp_file.enc").is_file())

    def test_decrypt_wrong_key(self):
        self.held_output.truncate(0); self.held_output.seek(0)
        
        Path("temp_file.txt").write_text("This is a secret message.")
        self.encrypt_app.encrypt("temp_file.txt")

        with patch("builtins.input", side_effect=["wrong.key"]):
            self.encrypt_app.make_new_key()
        with patch("builtins.input", side_effect=["wrong.key"]):
            self.encrypt_app.change_key()
        self.held_output.truncate(0); self.held_output.seek(0)

        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("temp_file.enc")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Invalid decryption key, password, or corrupted file.",
            self.held_output.getvalue(),
        )

    def test_encrypt_decrypt_large_file(self):
        self.held_output.truncate(0); self.held_output.seek(0)

        large_file_path = Path("large_file.bin")
        test_content = os.urandom(self.encrypt_app.CHUNK_SIZE + 123)
        large_file_path.write_bytes(test_content)

        self.encrypt_app.encrypt(str(large_file_path))
        self.assertTrue(Path("large_file.enc").is_file())
        self.held_output.truncate(0); self.held_output.seek(0)

        self.encrypt_app.decrypt("large_file.enc")
        self.assertTrue(Path("large_file.dec").is_file())
        self.assertEqual(Path("large_file.dec").read_bytes(), test_content)
        self.assertTrue(Path("large_file.enc").is_file())

    @patch("builtins.input", side_effect=["non_existent.key"])
    def test_remove_non_existent_key(self, mock_input):
        self.held_output.truncate(0); self.held_output.seek(0)
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.remove_key()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Key 'non_existent.key' not found", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["non_existent.txt"])
    def test_encrypt_non_existent_file(self, mock_input):
        self.held_output.truncate(0); self.held_output.seek(0)
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.encrypt("non_existent.txt")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("File 'non_existent.txt' not found", self.held_output.getvalue())

    @patch("builtins.input", side_effect=["non_existent.enc"])
    def test_decrypt_non_existent_file(self, mock_input):
        self.held_output.truncate(0); self.held_output.seek(0)
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("non_existent.enc")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("File 'non_existent.enc' not found", self.held_output.getvalue())

    def test_encrypt_decrypt_with_password(self):
        self.held_output.truncate(0); self.held_output.seek(0)
        
        test_content = b"a secret message for password test"
        Path("pass_file.txt").write_bytes(test_content)

        # Encrypt with password
        self.encrypt_app.encrypt("pass_file.txt", password="testpassword")
        self.assertTrue(Path("pass_file.enc").is_file())
        self.held_output.truncate(0); self.held_output.seek(0)

        # Decrypt with password
        self.encrypt_app.decrypt("pass_file.enc", password="testpassword")
        self.assertTrue(Path("pass_file.dec").is_file())
        self.assertEqual(Path("pass_file.dec").read_bytes(), test_content)
    
    def test_decrypt_with_wrong_password(self):
        self.held_output.truncate(0); self.held_output.seek(0)
        
        Path("wrong_pass.txt").write_bytes(b"some data")
        self.encrypt_app.encrypt("wrong_pass.txt", password="correct_password")
        self.held_output.truncate(0); self.held_output.seek(0)
        
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("wrong_pass.enc", password="wrong_password")
        
        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Invalid decryption key, password, or corrupted file.",
            self.held_output.getvalue(),
        )

    def test_backward_compatibility_decrypt_old_format(self):
        # Manually create an "old format" file (no version byte)
        key = self.encrypt_app._load_raw_key()
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        
        test_content = b"old format data"
        ciphertext = encryptor.update(test_content) + encryptor.finalize()
        tag = encryptor.tag

        with open("old_format.enc", "wb") as f:
            f.write(iv)
            f.write(ciphertext)
            f.write(tag)
            
        # Now try to decrypt it
        self.held_output.truncate(0); self.held_output.seek(0)
        self.encrypt_app.decrypt("old_format.enc")
        self.assertTrue(Path("old_format.dec").is_file())
        self.assertEqual(Path("old_format.dec").read_bytes(), test_content)

    def test_cli_execution(self):
        """Test the CLI entrypoint directly."""
        # Create a file to encrypt
        Path("cli_test.txt").write_text("CLI test data")

        # Test encryption via CLI
        # Use 'yes' to pipe 'y' to any confirmation prompts if needed
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "-e", "cli_test.txt"],
            capture_output=True, text=True, input='y'
        )
        self.assertEqual(result.returncode, 0, f"CLI encryption failed: {result.stderr}")
        self.assertTrue(Path("cli_test.enc").exists())

        # Test decryption via CLI
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "-d", "cli_test.enc"],
            capture_output=True, text=True, input='y'
        )
        self.assertEqual(result.returncode, 0, f"CLI decryption failed: {result.stderr}")
        self.assertTrue(Path("cli_test.dec").exists())
        self.assertEqual(Path("cli_test.dec").read_text(), "CLI test data")


if __name__ == "__main__":
    unittest.main()

