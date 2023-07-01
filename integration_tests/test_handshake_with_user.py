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

    def test_handshake(self):
        client = self._create_user_and_connection('testuser')
        client1 = self._create_user_and_connection('testuser1')

        response = client.send_handshake_request('testuser1')

        assert response == 'True'

    def _create_user_and_connection(self, username):
        client = Client('localhost', self.socket)
        client.connect()
        response = client.send_register_request(username, 'testpassword')
        assert response == 'True'
        response = client.send_login_request(username, 'testpassword')
        assert response == 'True'
        return client
