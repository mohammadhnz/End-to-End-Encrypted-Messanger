import os
import socket
import threading
import time
from random import randint

from client.main import Client
from server.controllers.serverhandler import ServerHandler


class TestIntegration:
    socket = 8000 + randint(1, 10)

    @classmethod
    def setup_class(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=ServerHandler('localhost', cls.socket).listen)
        cls.server_thread.start()
        time.sleep(1)  # Wait for the server to start listening

    @classmethod
    def teardown_class(cls):
        # Stop the server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect(('localhost', cls.socket))
        server_socket.send(b'shutdown')
        server_socket.close()
        cls.server_thread.join()
        if os.path.exists('users.json'):
            os.remove('users.json')

    def test_register_with_long_username_and_password(self):
        # Create a client and connect to the server
        client = Client('localhost', self.socket)
        client.connect()

        # Send a register request to the server
        response = client.send_register_request(
            "".join(['testuser' for i in range(10)]),
            "".join(['test_password123' for i in range(10)])
        )

        # Verify that the response is as expected
        assert response == 'True'

    def test_register_and_login(self):
        # Create a client and connect to the server
        client = Client('localhost', self.socket)
        client.connect()

        # Send a register request to the server
        response = client.send_register_request('testuser', 'testpassword')

        # Verify that the response is as expected
        assert response == 'True'

        # Send a login request to the server
        response = client.send_login_request('testuser', 'testpassword')

        # Verify that the response is as expected
        assert response == 'True'
