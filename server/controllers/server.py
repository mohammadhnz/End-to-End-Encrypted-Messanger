import socket
import threading

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
                message = self.encoder.decrypt(self.private_key, data)

                self.notify(message)
