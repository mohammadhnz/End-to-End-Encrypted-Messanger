import json
from datetime import datetime
from typing import Dict


class MessageHandler:
    def __init__(self, source, nonce=None):
        self.source = source
        self.nonce = nonce

    def create_message_string(self, message: str, seq=None, destionation=None) -> str:
        data = {
            'source': self.source,
            'message': message,
            'nonce': self.nonce or '',
            'seq': seq,
            'destionation': destionation,
            'timestamp': datetime.now()
        }
        return json.dumps(data)

    def decode_message_string(self, message) -> Dict:
        return json.loads(message)
