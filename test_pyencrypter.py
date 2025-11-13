import unittest
import os
import sys
import shutil
from unittest.mock import patch, MagicMock
from pathlib import Path
from io import StringIO

# Add the project directory to sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from enc_dec_file_univ import EncryptFile
from configparser import ConfigParser, NoSectionError, NoOptionError

# Mock BeautiPanel to capture output
class MockBeautiPanel:
    _messages = []

    @staticmethod
    def draw_panel(fontcolor: str, message: str, borderstyle: str = "red") -> None:
        MockBeautiPanel._messages.append(message)

    @staticmethod
    def get_messages():
        return MockBeautiPanel._messages

    @staticmethod
    def clear_messages():
        MockBeautiPanel._messages = []

# Patch BeautiPanel in enc_dec_file_univ
patch('enc_dec_file_univ.BeautiPanel', MockBeautiPanel).start()


class TestPyEncrypter(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for testing
        self.original_cwd = Path.cwd()
        self.test_dir = self.original_cwd / "test_temp_dir"
        self.test_dir.mkdir(exist_ok=True)
        os.chdir(self.test_dir)

        # Clear any previous messages from MockBeautiPanel
        MockBeautiPanel.clear_messages()

        # Ensure a clean state for each test
        self._cleanup_test_dir()

        # Initialize EncryptFile with the test directory
        self.encrypt_app = EncryptFile(script_path=self.test_dir)

    def tearDown(self):
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
        
        # Verify settings.ini and default.key are created
        self.assertTrue(Path("settings.ini").is_file())
        self.assertTrue(Path(self.encrypt_app.DEFAULT_KEY_NAME).is_file())
        self.assertTrue(Path(f"{self.encrypt_app.DEFAULT_KEY_NAME}.bak").is_file())
        self.assertEqual(self._get_settings_key(), self.encrypt_app.DEFAULT_KEY_NAME)
        self.assertIn(f"[+] Making a backup of {self.encrypt_app.DEFAULT_KEY_NAME}.bak", MockBeautiPanel.get_messages())
        self.assertIn(f"[+] Making the key read-only: {self.test_dir / self.encrypt_app.DEFAULT_KEY_NAME}.bak", MockBeautiPanel.get_messages())
        self.assertIn(f"[+] Making the key read-only: {self.test_dir / self.encrypt_app.DEFAULT_KEY_NAME}", MockBeautiPanel.get_messages())

    @patch('builtins.input', side_effect=['new_test.key'])
    def test_make_new_key(self, mock_input):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()

        self.encrypt_app.make_new_key()
        self.assertTrue(Path("new_test.key").is_file())
        self.assertIn("[+] Created new key: new_test.key. Make it read-only with -u", MockBeautiPanel.get_messages())

    @patch('builtins.input', side_effect=['new_active.key'])
    def test_change_key(self, mock_input):
        # Create a new key first
        with patch('builtins.input', side_effect=['new_active.key']):
            self.encrypt_app.make_new_key()
        MockBeautiPanel.clear_messages()

        self.encrypt_app.change_key()
        self.assertEqual(self._get_settings_key(), "new_active.key")
        self.assertIn("[!] Active key is: new_active.key", MockBeautiPanel.get_messages())

    @patch('builtins.input', side_effect=['test_readonly.key'])
    def test_make_key_readonly(self, mock_input):
        # Create a key first
        with patch('builtins.input', side_effect=['test_readonly.key']):
            self.encrypt_app.make_new_key()
        MockBeautiPanel.clear_messages()

        key_path = Path("test_readonly.key")
        self.encrypt_app.make_key_readonly()
        # Verify permissions (read-only for owner)
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o400)
        self.assertIn(f"[+] Making the key read-only: {self.test_dir / key_path}", MockBeautiPanel.get_messages())

    @patch('builtins.input', side_effect=['default.key'])
    def test_remove_default_key(self, mock_input):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()

        self.encrypt_app.remove_key()
        self.assertFalse(Path(self.encrypt_app.DEFAULT_KEY_NAME).is_file())
        self.assertFalse(Path(f"{self.encrypt_app.DEFAULT_KEY_NAME}.bak").is_file())
        self.assertIn(f"[+] The key {self.encrypt_app.DEFAULT_KEY_NAME} has been deleted", MockBeautiPanel.get_messages())
        self.assertIn(f"[+] The key {self.encrypt_app.DEFAULT_KEY_NAME}.bak has been deleted", MockBeautiPanel.get_messages())
        self.assertFalse(Path("settings.ini").read_text()) # settings.ini should be blank

    @patch('builtins.input', side_effect=['temp_file.txt', 'temp_file.enc'])
    def test_encrypt_decrypt_file(self, mock_input):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()

        # Create a test file
        test_content = "This is a secret message."
        Path("temp_file.txt").write_text(test_content)

        # Encrypt
        self.encrypt_app.encrypt("temp_file.txt")
        self.assertTrue(Path("temp_file.enc").is_file())
        self.assertIn("[+] File encrypted as temp_file.enc", MockBeautiPanel.get_messages())

        MockBeautiPanel.clear_messages()

        # Decrypt
        self.encrypt_app.decrypt("temp_file.enc")
        self.assertTrue(Path("temp_file.dec").is_file())
        self.assertEqual(Path("temp_file.dec").read_text(), test_content)
        self.assertIn("[+] File decrypted as temp_file.dec", MockBeautiPanel.get_messages())
        self.assertFalse(Path("temp_file.enc").is_file()) # Original encrypted file should be removed

    @patch('builtins.input', side_effect=['non_existent.key'])
    def test_remove_non_existent_key(self, mock_input):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()
        
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.remove_key()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("[!] Key non_existent.key not found", MockBeautiPanel.get_messages())

    @patch('builtins.input', side_effect=['non_existent.txt'])
    def test_encrypt_non_existent_file(self, mock_input):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()
        
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.encrypt("non_existent.txt")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("[!] File does not exist. Please check filename", MockBeautiPanel.get_messages())

    @patch('builtins.input', side_effect=['non_existent.enc'])
    def test_decrypt_non_existent_file(self, mock_input):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()
        
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("non_existent.enc")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("[!] File does not exist. Please check filename", MockBeautiPanel.get_messages())

    def test_decrypt_wrong_key(self):
        # Clear messages from initial setup
        MockBeautiPanel.clear_messages()

        # Create a test file
        test_content = "This is a secret message."
        Path("temp_file.txt").write_text(test_content)

        # Encrypt with default.key
        self.encrypt_app.encrypt("temp_file.txt")
        
        # Create a new key and make it active
        with patch('builtins.input', side_effect=['wrong.key']):
            self.encrypt_app.make_new_key()
        with patch('builtins.input', side_effect=['wrong.key']):
            self.encrypt_app.change_key()
        
        MockBeautiPanel.clear_messages()

        # Try to decrypt with wrong.key
        with self.assertRaises(SystemExit) as cm:
            self.encrypt_app.decrypt("temp_file.enc")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("[!] Decrypting with wrong key. Have you changed the encryption key?", MockBeautiPanel.get_messages())

if __name__ == '__main__':
    unittest.main()