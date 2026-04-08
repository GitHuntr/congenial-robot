import os

class SimpleConfig:
    def __init__(self):
        self.SECRET_KEY = 'your-secret-key-change-this'
        self.DB_PATH = 'ccaf.db'
        self.LOG_FILE = 'ccaf.log'
        self.HOST = '127.0.0.1'
        self.PORT = 5000
        self.DEBUG = True

config = SimpleConfig()
