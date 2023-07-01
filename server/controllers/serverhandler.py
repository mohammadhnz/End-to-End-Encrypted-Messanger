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
from utils.nonce import convert_nonce


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
        self.listen_sockets = dict()

    def listen(self):
        self.socket.listen()
        while True:
            conn, addr = self.socket.accept()
            print(f"Connected by {addr}")
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, connection):
        with connection:
            data = connection.recv(2 ** 15)
            message = self._decrypt_request(data)
            client_listen_port = int(message.content)
            client_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_listen_socket.connect((self.host, client_listen_port))
            self.listen_sockets[connection] = client_listen_socket
            while True:
                data = connection.recv(2 ** 15)
                if not data:
                    break

                message = self._decrypt_request(data)

                if connection not in self.online_users_dict:
                    ## handle answering to request without any login.
                    response = getattr(self, message.action)(message, connection)
                else:
                    ## handle answering to request without any login.
                    response = getattr(self, message.action)(message, connection)
                    client_public_key = User.get_user_public_key(self.online_users_dict[connection])
                    cipher_text, iv, key = AESEncoder().encrypt(response)
                    encrypted_keys = self.encoder.encrypt(client_public_key, iv + key)
                    response = json.dumps({
                        'encrypted_keys': str(encrypted_keys),
                        'cipher_text': str(cipher_text),
                        'message_type': message.action
                    })
                connection.sendall(response.encode())
                connection.sendall(self.encoder.sign_message(response.encode(), self.private_key))

    def _decrypt_request(self, data, *args) -> Message:
        data = json.loads(data.decode())
        sign = literal_eval(data['sign'])
        sign = self.encoder.decrypt(self.private_key.encode(), sign)
        iv = sign[:16]
        key = sign[16:]
        encoded_message = AESEncoder().decrypt(literal_eval(data['ciphertext']), iv, key)
        message: Message = MessageHandler.decode_message(encoded_message)
        return message

    def register(self, message, *args):
        data = json.loads(message.content)
        status, _ = Authentication().register(data['username'], data['password'])
        return str(status)

    def login(self, message, connection, *args):
        data = json.loads(message.content)
        status, username = Authentication().login(data['username'], data['password'], data['public_key'])
        self.online_users_dict[connection] = username
        return str(status)

    def get_online_users(self, message, connection):
        return json.dumps(list(self.online_users_dict.values()))

    def get_user_public_key(self, message, connection):
        username = json.loads(message.content)['username']
        return json.dumps({
            'user_public_key': str(User.get_user_public_key(username)),
            'converted_nonce': convert_nonce(message.nonce)
        })

    def get_connection_with_username(self, given_username):
        for connection, username in self.online_users_dict.items():
            if username == given_username:
                return connection

    def handle_handshake(self, message, connection):
        other_side_connection = self.get_connection_with_username(message.destination)
        other_side_connection.sendall(
            json.dumps({
                'message': message.content,
                'sign': str(self.encoder.sign_message(message.content.encode(), self.private_key))
            }).encode()
        )
        return 'True'
