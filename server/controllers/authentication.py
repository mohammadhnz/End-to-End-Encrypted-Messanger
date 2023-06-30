import hashlib
import os

from server.models import User


class Authentication:
    online_users = []

    def _load_users_list(self):
        pass

    def register(self, username, password):
        if User.username_exists(username):
            return False, f"User with username {username} exists."
        self._store_user_data(username, password)
        return True, "Good luck"

    def _store_user_data(self, username, password):
        password_hash, salt = self._generate_password_hash(password)
        user = User(username, None, password_hash, salt)
        User.objects.append(user)
        User.save()

    def _generate_password_hash(self, password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        password_hash = salt + key
        return password_hash, salt

    def login(self, username, password, public_key):
        if not self._authenticate(username, password):
            return False, "Wrong username or password"
        self._store_public_key(username, public_key)
        self._add_to_online_users(username)
        return True, "Good"

    def _authenticate(self, username, password):
        return User.username_exists(username) and User.validate_password(username, password)

    def _store_public_key(self, username, public_key):
        return User.update_public_key(username, public_key)

    def _add_to_online_users(self, username):
        Authentication.online_users.append(username)
