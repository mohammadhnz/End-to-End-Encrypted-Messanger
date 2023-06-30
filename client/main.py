import socket

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

    def connect(self):
        self.socket.connect((self.host, self.port))

    def send_request(self, message):
        ciphertext = self._encrypt_message(message)
        self.socket.sendall(ciphertext)
        response = self.socket.recv(2048)
        signature = self.socket.recv(2048)
        status = self.encoder.verify_signature(signature, self.server_public_key, response.decode())
        return status, response

    def send_register_request(self, username, password):
        message = MessageHandler.create_register_message(username, password)
        print(message)
        response = self.send_request(
            message
        )
        return response

    def send_login_request(self, username, password):
        public_key = '123'
        message = MessageHandler.create_login_message(username, password, public_key)
        response = self.send_request(
            message
        )
        return response

    def _encrypt_message(self, message):
        ciphertext, iv, key = AESEncoder().encrypt(message)
        sign = self.encoder.encrypt(self.server_public_key, iv + key)
        return self.encoder.encrypt(self.server_public_key, message)


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
