from server.controllers.server import Server
from server.models import User
from utils.base_classes.observer import Observer
from utils.connection_env import SERVER_PORT


class ConsoleObserver(Observer):
    def update(self, message):
        print(f"Received message: {message}")


if __name__ == "__main__":
    print("We are trying to connect")
    server = Server("127.0.0.2", SERVER_PORT)
    print("connection is established")
    User.load_all_users()
    console_observer = ConsoleObserver()
    server.attach(console_observer)
    server.listen()
