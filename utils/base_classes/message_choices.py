from enum import Enum


class MessageType(Enum):
    REGISTER = 'register'
    LOGIN = 'login'
    ONLINE_USERS_REQUEST = 'online_users_request'
