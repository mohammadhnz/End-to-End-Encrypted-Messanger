from enum import Enum


class MessageType(Enum):
    REGISTER = 'register'
    LOGIN = 'login'
    ONLINE_USERS_REQUEST = 'get_online_users'
    USER_PUBLIC_REQUEST = 'get_user_public_key'
    HANDSHAKE = 'handle_handshake'
    HANDSHAKE_RESPONSE = 'handle_handshake_response'
    HANDSHAKE_FINALIZE = 'finalize_handshake'
    CHAT_MESSAGE_REQUEST = 'send_chat_message'
    CHAT_MESSAGE_ACK = 'acknowledge_chat_message'
