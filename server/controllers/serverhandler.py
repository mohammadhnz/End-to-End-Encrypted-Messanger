import json
import socket
import threading
from ast import literal_eval

from server.controllers.authentication import Authentication
from server.models import User
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
        self.online_users_dict = dict()

    def listen(self):
        self.socket.listen()
        while True:
            conn, addr = self.socket.accept()
            print(f"Connected by {addr}")
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, connection):
        with connection:
            while True:
                data = connection.recv(2 ** 13)
                if not data:
                    break
                ## load data as dict which has sign and ciphertext
                message = self._decrypt_request(data)

                if connection not in self.online_users_dict:
                    ## handle answering to request without any login.
                    response = getattr(self, message.action)(message.content, connection)
                else:
                    ## handle answering to request without any login.
                    response = getattr(self, message.action)(message.content, connection)
                    client_public_key = User.get_user_public_key(self.online_users_dict[connection])
                    cipher_text, iv, key = AESEncoder().encrypt(response)
                    encrypted_keys = self.encoder.encrypt(client_public_key, iv + key)
                    response = json.dumps({
                        'encrypted_keys': str(encrypted_keys),
                        'cipher_text': str(cipher_text)
                    })
                connection.sendall(response.encode())
                connection.sendall(self.encoder.sign_message(response.encode(), self.private_key))

    def _decrypt_request(self, data, *args) -> Message:
        data = json.loads(data)
        sign = literal_eval(data['sign'])
        sign = self.encoder.decrypt(self.private_key.encode(), sign)
        iv = sign[:16]
        key = sign[16:]
        encoded_message = AESEncoder().decrypt(literal_eval(data['ciphertext']), iv, key)
        message: Message = MessageHandler.decode_message(encoded_message)
        return message

    def register(self, content, *args):
        data = json.loads(content)
        status, _ = Authentication().register(data['username'], data['password'])
        return str(status)

    def login(self, content, connection, *args):
        data = json.loads(content)
        status, username = Authentication().login(data['username'], data['password'], data['public_key'])
        self.online_users_dict[connection] = username
        return str(status)

    def get_online_users(self, content, connection):
        return json.dumps(list(self.online_users_dict.values()))
