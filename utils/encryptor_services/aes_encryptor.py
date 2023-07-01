import hmac
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESEncoder:
    @classmethod
    def encrypt(cls, message, iv=None, key=None):
        if not iv:
            iv = os.urandom(16)
        if not key:
            key = os.urandom(32)
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        mac = hmac.new(key, ciphertext, digestmod='sha256').digest()
        return mac + ciphertext, iv, key

    @classmethod
    def decrypt(cls, ciphertext, iv, key):
        mac = ciphertext[:32]
        ciphertext = ciphertext[32:]
        expected_mac = hmac.new(key, ciphertext, digestmod='sha256').digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError('MAC verification failed')
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message.decode()
