import os

KEYS_DIR: str = "keys"

MESSAGES_DIR: str = "messages"

if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

if not os.path.exists(MESSAGES_DIR):
    os.makedirs(MESSAGES_DIR)
