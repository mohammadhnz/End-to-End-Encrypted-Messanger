import socket
import threading

from utils.base_classes.observer import Observer
from utils.base_classes.subject import Subject
from utils.connection_env import SERVER_PORT
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
                self.notify(self.encoder.decrypt(self.private_key, data))


class ConsoleObserver(Observer):
    def update(self, message):
        print(f"Received message: {message}")


if __name__ == "__main__":
    server = Server("localhost", SERVER_PORT)

    console_observer = ConsoleObserver()
    server.attach(console_observer)
    server.listen()
