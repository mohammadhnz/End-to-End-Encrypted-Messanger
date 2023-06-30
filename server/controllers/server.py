import json
import socket
import threading

from server.controllers.authentication import Authentication
from utils.base_classes.message import MessageHandler, Message
from utils.base_classes.subject import Subject
from utils.encryptor_services.rsa_encryptor import RSAEncoder


class Server(Subject):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        with open("server_private_key.pem", "rb") as key_file:
            self.private_key = key_file.read().decode()
        self.encoder = RSAEncoder()

    def listen(self):
        self.socket.listen()
        while True:
            conn, addr = self.socket.accept()
            print(f"Connected by {addr}")
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, conn):
        with conn:
            while True:
                data = conn.recv(2 ** 13)

                if not data:
                    break
                encoded_message = self.encoder.decrypt(self.private_key, data)
                message: Message = MessageHandler.decode_message(encoded_message)
                response = getattr(self, message.action)(message.content)
                conn.sendall(response.encode())
                conn.sendall(self.encoder.sign_with_private_key(self.private_key, response))
                self.notify(message.content)
                self.notify(message.action)

    def register(self, content):
        data = json.loads(content)
        status, _ = Authentication().register(data['username'], data['password'])
        return str(status)

    def login(self, content):
        data = json.loads(content)
        status, _ = Authentication().login(data['username'], data['password'], data['public_key'])
        return str(status)
