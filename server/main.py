from server.models import Server
from utils.base_classes.observer import Observer
from utils.connection_env import SERVER_PORT


class ConsoleObserver(Observer):
    def update(self, message):
        print(f"Received message: {message}")


if __name__ == "__main__":
    server = Server("localhost", SERVER_PORT)

    console_observer = ConsoleObserver()
    server.attach(console_observer)
    server.listen()
