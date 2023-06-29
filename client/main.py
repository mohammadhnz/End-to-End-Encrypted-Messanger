import socket
import threading
from typing import List

from utils.connection_env import SERVER_PORT
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

    def send(self, message):
        self.socket.sendall(self.encoder.encrypt(self.server_public_key, message))


if __name__ == "__main__":
    client1 = Client("localhost", SERVER_PORT)
    client1.connect()
    while (text := input()) != 'exit':
        client1.send(text)
