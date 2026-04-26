import unittest
import os
from src.simple_rsa import generate_keys, encrypt, decrypt, PublicKey, PrivateKey

class TestSimpleRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub_key, cls.priv_key = generate_keys(512)

    def test_short_message_encryption(self):
        message = "Hello, World!"
        ciphertext = encrypt(message, self.pub_key)
        decrypted = decrypt(ciphertext, self.priv_key)
        self.assertEqual(message, decrypted)

    def test_long_message_chunking(self):
        message = "A" * 2000
        ciphertext = encrypt(message, self.pub_key)
        decrypted = decrypt(ciphertext, self.priv_key)
        self.assertEqual(message, decrypted)

    def test_invalid_ciphertext_handling(self):
        with self.assertRaises(ValueError):
            decrypt("This is not valid base64 data", self.priv_key)

    def test_key_export_import(self):
        self.pub_key.export_key("test_pub.json")
        self.priv_key.export_key("test_priv.json")

        self.assertTrue(os.path.exists("test_pub.json"))
        self.assertTrue(os.path.exists("test_priv.json"))

        imported_pub = PublicKey.import_key("test_pub.json")
        imported_priv = PrivateKey.import_key("test_priv.json")

        self.assertEqual(self.pub_key.n, imported_pub.n)
        self.assertEqual(self.pub_key.e, imported_pub.e)
        self.assertEqual(self.priv_key.d, imported_priv.d)

        os.remove("test_pub.json")
        os.remove("test_priv.json")

if __name__ == "__main__":
    unittest.main()
