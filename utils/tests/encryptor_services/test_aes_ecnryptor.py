import unittest

from utils.encryptor_services.aes_encryptor import AESEncoder


class TestAESEncoder(unittest.TestCase):
    def test_encrypt_decrypt_works_correctly(self):
        message = 'This is a test message.'
        ciphertext, iv, key = AESEncoder.encrypt(message)
        decrypted_message = AESEncoder.decrypt(ciphertext, iv, key)
        self.assertEqual(decrypted_message, message)

    def test_decrypt_raises_Value_Error_when_mac_is_invalid(self):
        message = 'This is a test message.'
        ciphertext, iv, key = AESEncoder.encrypt(message)
        modified_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
        with self.assertRaises(ValueError):
            AESEncoder.decrypt(modified_ciphertext, iv, key)

    def test_random_long_messages_works_correctly(self):
        import random
        for i in range(100):
            message = str([str(random.randint(0, 255) ** 10) for j in range(1000)])
            ciphertext, iv, key = AESEncoder.encrypt(message)
            decrypted_message = AESEncoder.decrypt(ciphertext, iv, key)
            self.assertEqual(decrypted_message, message)
