import hashlib
import json

from server.controllers.data_io import DataIO


class User:
    objects = []
    data_io = DataIO('users.json')

    def __init__(self, username, public_key, password_hash, salt):
        self.username = username
        self.public_key = public_key
        self.password_hash = password_hash
        self.salt = salt

    @classmethod
    def load_all_users(cls):
        data = cls.data_io.read_data()
        users = [
            cls(
                user['username'],
                user['public_key'],
                user['password_hash'],
                user['salt']
            ) for user in data]
        cls.objects = users

    @classmethod
    def username_exists(cls, username):
        for user in cls.objects:
            if user.username == username:
                return True
        return False

    @classmethod
    def save(cls):
        data = [
            {
                'username': user.username,
                'public_key': user.public_key,
                'password_hash': str(user.password_hash),
                'salt': str(user.salt)
            } for user in cls.objects
        ]
        cls.data_io.write_data(data)

    def to_dict(self):
        return {'username': self.username, 'password_hash': self.password_hash}

    @classmethod
    def validate_password(cls, username, password):
        for user in cls.objects:
            if user.username == username:
                if user.password_hash == user.salt + hashlib.pbkdf2_hmac(
                        'sha256', password.encode('utf-8'), user.salt, 100000
                ):
                    return True
                return False
        return False
    @classmethod
    def update_public_key(cls, username, publickey):
        for user in cls.objects:
            if user.username == username:
                user.public_key = publickey
                cls.save()
                return True