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

    def test_retrieve_online_users(self):
        client = self._create_user_and_connection('testuser', 10)
        client1 = self._create_user_and_connection('testuser1', 11)

        response = client.send_online_users_list_request()

        assert response == '["testuser", "testuser1"]'

    def _create_user_and_connection(self, username, id):
        client = Client('localhost', self.socket, id)
        client.connect()
        response = client.send_register_request(username, 'testpassword')
        assert response == 'True'
        response = client.send_login_request(username, 'testpassword')
        assert response == 'True'
        return client
