from server.models import User


class Authentication:
    def _load_users_list(self):
        pass

    def register(self, username, password):
        if not self._check_user_is_unique(username):
            return False, ""
        self._store_user_data(username, password)
        return True, ""

    def _check_user_is_unique(self, username):
        pass

    def _store_user_data(self, username, password):
        pass

    def login(self, username, password, public_key):
        if not self._authenticate(username, password):
            raise Exception('wrong username or password.')
        self._store_public_key(username, public_key)
        self._add_to_online_users(username)
        return User(username, public_key)

    def _authenticate(self, username, password):
        pass

    def _store_public_key(self, username, public_key):
        pass

    def _add_to_online_users(self, username):
        pass
