from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSAEncoder:
    def __init__(self, key=None):
        if key is None:
            self.private_key, self.public_key = self.generate_key()
        else:
            self.private_key, self.public_key = self.load_key(key)

    @staticmethod
    def generate_key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def load_key(key):
        private_key = serialization.load_pem_private_key(
            key.encode(),
            password=None
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, key: str, plaintext: str) -> bytes:
        key = serialization.load_pem_public_key(key.encode())
        ciphertext = key.encrypt(
            plaintext.encode() if isinstance(plaintext, str) else plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, key: str, ciphertext: bytes) -> str:
        key = serialization.load_pem_private_key(
            key.encode(),
            password=None
        )
        plaintext = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sign_with_private_key(self, private_key, message):
        sender_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None
        )
        signature = sender_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, signature, public_key, message):
        try:
            recipient_key = serialization.load_pem_public_key(public_key.encode())
            recipient_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def load_key_from_file(self, filename):
        with open(filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        public_key = private_key.public_key()
        self.private_key, self.public_key = private_key, public_key

    def load_public_key_from_file(self, filename):
        with open(filename, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        self.public_key = public_key

    def save_private_key_to_file(self, filename, private_key):
        with open(filename, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

    def save_public_key_to_file(self, filename, public_key):
        with open(filename, "wb") as key_file:
            key_file.write(
                self._encode_public_key(public_key))

    def _encode_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _encode_private_key(self, private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
