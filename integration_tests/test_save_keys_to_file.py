import os
import signal
import socket
import threading
import time
from random import randint

from client.main import Client
from server.controllers.serverhandler import ServerHandler
def terminate_threads():
    # get all threads
    threads = threading.enumerate()

    # iterate over all threads and terminate them
    for thread in threads:
        thread_id = thread.ident
        os.kill(thread_id, signal.SIGKILL)


class TestIntegration:
    socket = 8100 + randint(1, 10)

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
        # terminate_threads()

    def test_handshake(self):
        client = self._create_user_and_connection('testuser', 10)
        client1 = self._create_user_and_connection('testuser1', 11)
        client.send_handshake_request('testuser1')
        response = client.send_message('testuser1', 'hi ali')
        time.sleep(1)
        assert len(client.messages['testuser1']) == 1
        assert len(client1.messages['testuser']) == 1
        response = client1.send_message('testuser', 'hi morad')
        time.sleep(1)
        assert len(client.messages['testuser1']) == 2
        assert len(client1.messages['testuser']) == 2
        client.save_keys_to_file()
        client.save_messages_to_file()
        client1.save_keys_to_file()
        client1.save_messages_to_file()

    def _create_user_and_connection(self, username, id):
        client = Client('localhost', self.socket, id)
        client.connect()
        response = client.send_register_request(username, 'testpassword')
        assert response == 'True'
        response = client.send_login_request(username, 'testpassword')
        assert response == 'True'
        return client
