import json
import socket
from ast import literal_eval

from utils.base_classes.message import MessageHandler
from utils.connection_env import SERVER_PORT
from utils.encryptor_services.aes_encryptor import AESEncoder
from utils.encryptor_services.rsa_encryptor import RSAEncoder


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with open("server_public_key.pem", "rb") as key_file:
            self.server_public_key = key_file.read().decode()
        self.encoder = RSAEncoder()
        self.private_key = None
        self.public_key = None
        self.username = None

    def connect(self):
        self.socket.connect((self.host, self.port))

    def send_request(self, message):
        ciphertext = self._encrypt_message(message)
        self.socket.sendall(ciphertext)
        response = self.socket.recv(2048)
        signature = self.socket.recv(2048)
        status = self.encoder.verify_signature(response, signature, self.server_public_key)
        if not status:
            raise Exception("Sth")
        return response.decode()

    def send_register_request(self, username, password):
        message = MessageHandler.create_register_message(username, password)
        response = self.send_request(
            message
        )
        return response

    def send_login_request(self, username, password):
        private_key, public_key = self.encoder.generate_key()
        self.public_key = self.encoder._encode_public_key(public_key)
        self.private_key = self.encoder._encode_private_key(private_key)
        message = MessageHandler.create_login_message(username, password, str(self.public_key))
        response = self.send_request(
            message
        )
        if response:
            self.username = username
        return response

    def send_online_users_list_request(self):
        message = MessageHandler.create_online_users_message(self.username)
        return self.send_secure_request(message)

    def send_secure_request(self, message):
        response = self.send_request(message)
        response = self._decrypt_response(response)
        return response

    def _decrypt_response(self, response):
        response = json.loads(response)
        cipher_text = literal_eval(response['cipher_text'])
        encrypted_keys = literal_eval(response['encrypted_keys'])
        keys = self.encoder.decrypt(self.private_key, encrypted_keys)
        response = AESEncoder.decrypt(cipher_text, keys[:16], keys[16:])
        return response

    def _encrypt_message(self, message):
        ciphertext, iv, key = AESEncoder().encrypt(message)
        sign = self.encoder.encrypt(self.server_public_key.encode(), iv + key)
        return json.dumps({'sign': str(sign), 'ciphertext': str(ciphertext)}).encode()


if __name__ == "__main__":
    client1 = Client("localhost", SERVER_PORT)
    client1.connect()
    status, response = client1.send_register_request('123456789', '1234')
    print(status)
    # status, response = client1.send_login_request('ali3', '123489')
    # status, response = client1.send_login_request('ali3', '123456789')
    # if not status:
    #     print("invalid Sign")
    # else:
    #     print(response)
    # while (text := input()) != 'exit':
    #     client1.send_request(text)
