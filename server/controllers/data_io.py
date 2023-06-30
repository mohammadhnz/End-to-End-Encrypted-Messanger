import json
import os

class DataIO:
    def __init__(self, filename):
        self.filename = filename

    def read_data(self):
        try:
            with open(self.filename, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = []
        return data

    def write_data(self, data):
        with open(self.filename, 'w') as f:
            json.dump(data, f, indent=3)

    def create_file(self):
        if not os.path.isfile(self.filename):
            with open(self.filename, 'w') as f:
                f.write('[]')