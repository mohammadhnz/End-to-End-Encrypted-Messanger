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
        print(source)
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
        message = Message(
            action=MessageType.REGISTER.value,
            destination='Server',
            source='',
            nonce='',
            seq='',
            time_stamp='',
            content=json.dumps({'username': username, 'password': password}),
        )
        return json.dumps({
            'destination': message.destination,
            'content': message.content,
            'source': message.source,
            'action': message.action,
            'nonce': message.nonce,
            'seq': message.seq,
            'time_stamp': message.time_stamp,
        }, indent=4)

    def decode_message(self, encoded_message: str) -> Message:
        data = json.loads(encoded_message)
        data = {
            key: value[0] if isinstance(value, list) or isinstance(value, tuple) else value
            for key, value in data.items()
        }
        print(data)
        message = Message(
            data['source'],
            data['content'],
            data['action'],
            data['nonce'],
            data['seq'],
            data['destination'],
            data['time_stamp'],
        )
        return message, data
