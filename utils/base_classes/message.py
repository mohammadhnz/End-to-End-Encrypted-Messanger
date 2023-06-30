import json

from utils.base_classes.message_choices import MessageType


class Message:
    def __init__(
            self,
            source,
            content,
            action,
            nonce,
            seq,
            destination,
            time_stamp
    ):
        self.source = source,
        self.content = content,
        self.action = action,
        self.nonce = nonce,
        self.seq = seq,
        self.destination = destination
        self.time_stamp = time_stamp


class MessageHandler:
    @classmethod
    def create_register_message(cls, username, password):
        content = json.dumps({'username': username, 'password': password})
        action = MessageType.REGISTER.value
        return cls._insecure_message(content, action)

    @classmethod
    def _insecure_message(cls, content, action):
        message = Message(
            action=action,
            destination='Server',
            source=None,
            nonce=None,
            seq=None,
            time_stamp=None,
            content=content,
        )
        return json.dumps({
            'destination': message.destination,
            'content': message.content,
            'source': message.source,
            'action': message.action,
            'nonce': message.nonce,
            'seq': message.seq,
            'time_stamp': message.time_stamp,
        })

    @classmethod
    def create_login_message(cls, username, password, public_key):
        content = json.dumps({'username': username, 'password': password, 'public_key': public_key})
        action = MessageType.LOGIN.value
        return cls._insecure_message(content, action)

    @classmethod
    def decode_message(cls, encoded_message: str) -> Message:
        data = json.loads(encoded_message)
        data = {
            key: value[0] if isinstance(value, list) or isinstance(value, tuple) else value
            for key, value in data.items()
        }
        message = Message(
            data['source'],
            data['content'],
            data['action'],
            data['nonce'],
            data['seq'],
            data['destination'],
            data['time_stamp'],
        )
        for key, value in data.items():
            setattr(message, key, value)

        return message

    @classmethod
    def create_online_users_message(cls, username):
        content = json.dumps({'username': username})
        action = MessageType.ONLINE_USERS_REQUEST.value
        return cls._insecure_message(content, action)

