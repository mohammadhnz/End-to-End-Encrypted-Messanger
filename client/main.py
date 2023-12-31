import hashlib
import json
import os
import socket
import threading
from ast import literal_eval
from collections import defaultdict
from random import randint

from utils.base_classes.message import MessageHandler
from utils.connection_env import SERVER_PORT
from utils.encryptor_services.aes_encryptor import AESEncoder
from utils.encryptor_services.rsa_encryptor import RSAEncoder
from utils.nonce import create_nonce, validate_nonce, convert_nonce


def random_seq_num():
    return randint(100, 500)


class Client:
    def __init__(self, host, port, id=10):
        self.messages = defaultdict(list)
        self.session_keys = defaultdict(list)
        self.users_public_keys = dict()
        self.sequence_numbers = defaultdict(int)
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with open("server_public_key.pem", "rb") as key_file:
            self.server_public_key = key_file.read().decode()
        self.encoder = RSAEncoder()
        self.private_key = None
        self.public_key = None
        self.username = None
        self.last_nonce = None
        self.temp_user_name = None
        self.id = id
        self.receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receive_socket.bind((host, port + id))

    def save_keys_to_file(self):
        if not self.username:
            raise Exception('You are not logged in.')
        hash_obj = hashlib.sha512(self.password.encode()).digest()
        iv = hash_obj[:16]
        key = hash_obj[16:48]
        keys = json.dumps(
            {
                'public_keys': {user: str(key) for user, key in self.users_public_keys.items()},
                'session_keys': {user: str(key) for user, key in self.session_keys.items()}
            }
        )
        cipher_texts, _, _ = AESEncoder.encrypt(keys, iv, key)
        with open(f"{self.username}_keys", "wb") as file:
            file.write(cipher_texts)

    def show_messages(self, user):
        messages_list = []
        messages = self.messages[user]
        for message, key_id in messages:
            iv, key = self.session_keys[user][-1]
            print(message)
            decrypted_message = AESEncoder.decrypt(literal_eval(message), iv, key)
            messages_list.append(decrypted_message)
        return messages_list
    def save_messages_to_file(self):
        if not self.username:
            raise Exception('You are not logged in.')
        hash_obj = hashlib.sha512(self.password.encode()).digest()
        iv = hash_obj[:16]
        key = hash_obj[16:48]
        messages = json.dumps(
            {
                'messages': {user: [str(item) for item in msgs] for user, msgs in self.messages.items()},
            }
        )
        cipher_texts, _, _ = AESEncoder.encrypt(messages, iv, key)
        with open(f"{self.username}_messages", "wb") as file:
            file.write(cipher_texts)

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.start_listening_thread()
        self.send_request(MessageHandler.create_listen_port_request(self.port + self.id), no_response=True)

    def start_listening_thread(self):
        threading.Thread(target=self.listen).start()

    def send_request(self, message, no_response=False):
        ciphertext = self._encrypt_message(message)
        self.socket.sendall(ciphertext)
        if no_response:
            return None
        response = self.socket.recv(4096 * 16)
        signature = self.socket.recv(4096 * 16)
        status = self.encoder.verify_signature(response, signature, self.server_public_key)
        if not status:
            raise Exception("Sth")
        return response.decode()

    def send_register_request(self, username, password):
        message = MessageHandler.create_register_message(username, password)
        response = self.send_request(
            message
        )
        return response

    def send_login_request(self, username, password):
        private_key, public_key = self.encoder.generate_key()
        self.public_key = self.encoder._encode_public_key(public_key)
        self.private_key = self.encoder._encode_private_key(private_key)
        message = MessageHandler.create_login_message(username, password, str(self.public_key))
        response = self.send_request(
            message
        )
        if response:
            self.username = username
            self.password = password
        return response

    def send_online_users_list_request(self):
        message = MessageHandler.create_online_users_message(self.username)
        return self.send_secure_request(message)

    def send_handshake_request(self, username):
        self._update_public_key_of_receiver(username)
        return self._initialize_handshake_process(username)

    def send_message(self, username, message):
        if username not in self.session_keys:
            raise Exception(f'no session key for user{username}')
        self.last_nonce = create_nonce()
        message_packet = json.dumps({
            'message': message,
            'sequence_number': self.sequence_numbers[username],
            'nonce': self.last_nonce
        })
        iv, key = self.session_keys[username][-1]
        cipher_text, _, _ = AESEncoder.encrypt(message_packet, iv, key)
        message = MessageHandler.create_chat_message_request(str(cipher_text), username, self.username)
        return self.send_secure_request(message)

    def _initialize_handshake_process(self, username):
        self.last_nonce = create_nonce()
        iv, key = os.urandom(16), os.urandom(32)
        self.session_keys[username].append((iv, key))
        handshake_data = json.dumps({
            'username': self.username,
            'iv': str(iv),
            'key': str(key),
            'nonce': self.last_nonce,
            'pub': str(self.public_key)
        })

        encrypted_keys = self.encoder.encrypt(self.users_public_keys[username], iv + key)
        cipher_text, _, _ = AESEncoder.encrypt(handshake_data, iv, key)
        handshake_packet = json.dumps({
            'encrypted_keys': str(encrypted_keys),
            'cipher_text': str(cipher_text)
        })
        message = MessageHandler.create_handshake_request(handshake_packet, username)
        return self.send_secure_request(message)

    def _update_public_key_of_receiver(self, username):
        self.last_nonce = create_nonce()
        message = MessageHandler.create_user_public_key_request(username, self.last_nonce)
        response = json.loads(self.send_secure_request(message))
        if validate_nonce(self.last_nonce, response['converted_nonce']):
            self.users_public_keys[username] = literal_eval(response['user_public_key'])
            return
        raise Exception('Failed to update user\'s publick key.')

    def send_secure_request(self, message, no_response=False):
        response = self.send_request(message, no_response)
        response = self._decrypt_response(response)
        return response

    def _decrypt_response(self, response):
        response = json.loads(response)
        cipher_text = literal_eval(response['cipher_text'])
        encrypted_keys = literal_eval(response['encrypted_keys'])
        keys = self.encoder.decrypt(self.private_key, encrypted_keys)
        response = AESEncoder.decrypt(cipher_text, keys[:16], keys[16:])
        return response

    def _encrypt_message(self, message):
        ciphertext, iv, key = AESEncoder().encrypt(message)
        sign = self.encoder.encrypt(self.server_public_key.encode(), iv + key)
        return json.dumps({'sign': str(sign), 'ciphertext': str(ciphertext)}).encode()

    def listen(self):
        self.receive_socket.listen()
        while True:
            conn, addr = self.receive_socket.accept()
            print(f"Connected by {addr}")
            threading.Thread(target=self.handle_server, args=(conn,)).start()

    def handle_server(self, connection):
        with connection:
            while True:
                data = connection.recv(2 ** 16)
                data = json.loads(data)
                message = data['message']
                sign = literal_eval(data['sign'])
                stage = data['stage']
                status = self.encoder.verify_signature(message.encode(), sign, self.server_public_key)
                ## handle hanshake 3rd step
                try:
                    self._handleee(data, message, stage)
                except BaseException as e:
                    a = e
                    print('1')

    def _handleee(self, data, message, stage):
        if stage == '3':
            message = json.loads(message)
            encrypted_keys = literal_eval(message['encrypted_keys'])
            cipher_text = literal_eval(message['cipher_text'])
            keys = self.encoder.decrypt(self.private_key, encrypted_keys)
            iv = keys[:16]
            key = keys[16:]
            plaintext = AESEncoder.decrypt(cipher_text, iv, key)
            plaintext = json.loads(plaintext)
            converted_nonce = convert_nonce(plaintext['nonce'])
            self.session_keys[plaintext['username']].append((iv, key))
            self.last_nonce = create_nonce()
            data_to_send = json.dumps({
                'nonce': self.last_nonce,
                'converted_nonce': converted_nonce,
            })
            cipher_text, _, _ = AESEncoder.encrypt(data_to_send, iv, key)
            message = MessageHandler.create_handshake_response_request(
                str(cipher_text),
                plaintext['username'],
                data['destination']
            )
            self.send_secure_request(message)
        elif stage == '5':
            iv, key = self.session_keys[data['sender']][-1]
            message = json.loads(AESEncoder().decrypt(literal_eval(message), iv, key))
            # if not validate_nonce(self.last_nonce, message['converted_nonce']):
            #     raise Exception('Fuck you')
            converted_nonce = convert_nonce(message['nonce'])
            data_to_send = json.dumps({
                'converted_nonce': converted_nonce,
            })
            cipher_text, _, _ = AESEncoder.encrypt(data_to_send, iv, key)
            message = MessageHandler.create_handshake_finalize_request(
                str(cipher_text),
                data['sender'],
                data['user']
            )
            self.send_secure_request(message)
        elif stage == '7':
            iv, key = self.session_keys[data['sender']][-1]
            message = json.loads(AESEncoder().decrypt(literal_eval(message), iv, key))
            if not validate_nonce(self.last_nonce, message['converted_nonce']) and self.session_keys[data['sender']]:
                self.session_keys[data['sender']].pop()
                raise Exception('Fuck you')
        elif stage == '9':
            iv, key = self.session_keys[data['sender']][-1]
            message_packet = json.loads(AESEncoder().decrypt(literal_eval(message), iv, key))
            if message_packet['sequence_number'] != self.sequence_numbers[data['sender']]:
                raise Exception('Fuck you hacker I have no asab')
            self.messages[data['sender']].append((message, len(self.session_keys[data['sender']])))
            self.sequence_numbers[data['sender']] += 1
            ack_packet = json.dumps({
                'message': message,
                'converted_nonce': convert_nonce(message_packet['nonce']),
                'new_sequence_number': self.sequence_numbers[data['sender']]
            })
            cipher_text, _, _ = AESEncoder.encrypt(ack_packet, iv, key)
            message = MessageHandler.create_chat_message_ack_request(
                str(cipher_text),
                data['sender'],
                self.username
            )
            self.send_secure_request(message)
        elif stage == '11':
            iv, key = self.session_keys[data['sender']][-1]
            message_packet = json.loads(AESEncoder().decrypt(literal_eval(message), iv, key))
            if message_packet['new_sequence_number'] != self.sequence_numbers[data['sender']] + 1:
                raise Exception("wrong seq number")
            if not validate_nonce(self.last_nonce, message_packet['converted_nonce']):
                raise Exception("wrong nonce")
            self.messages[data['sender']].append(message_packet['message'])
            self.sequence_numbers[data['sender']] += 1


if __name__ == "__main__":
    client1 = Client("localhost", SERVER_PORT)
    client1.connect()
    status, response = client1.send_register_request('123456789', '1234')
    print(status)
    # status, response = client1.send_login_request('ali3', '123489')
    # status, response = client1.send_login_request('ali3', '123456789')
    # if not status:
    #     print("invalid Sign")
    # else:
    #     print(response)
    # while (text := input()) != 'exit':
    #     client1.send_request(text)
