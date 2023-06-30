import json
import socket
import threading
from ast import literal_eval

from server.controllers.authentication import Authentication
from utils.base_classes.message import MessageHandler, Message
from utils.base_classes.subject import Subject
from utils.encryptor_services.aes_encryptor import AESEncoder
from utils.encryptor_services.rsa_encryptor import RSAEncoder


class ServerHandler(Subject):
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
                ## load data as dict which has sign and ciphertext
                message = self._decrypt_request(data)
                if message.action in ['register', 'login']:
                    response = getattr(self, message.action)(message.content)
                    conn.sendall(response.encode())
                    conn.sendall(self.encoder.sign_message(response.encode(), self.private_key))
                else:
                    print('')
                    self.notify(message.content)
                    self.notify(message.action)

    def _decrypt_request(self, data) -> Message:
        data = json.loads(data)
        sign = literal_eval(data['sign'])
        sign = self.encoder.decrypt(self.private_key, sign)
        iv = sign[:16]
        key = sign[16:]
        encoded_message = AESEncoder().decrypt(literal_eval(data['ciphertext']), iv, key)
        message: Message = MessageHandler.decode_message(encoded_message)
        return message

    def register(self, content):
        data = json.loads(content)
        status, _ = Authentication().register(data['username'], data['password'])
        return str(status)

    def login(self, content):
        data = json.loads(content)
        status, _ = Authentication().login(data['username'], data['password'], data['public_key'])
        return str(status)
