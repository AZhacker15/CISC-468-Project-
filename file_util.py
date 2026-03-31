import os
from crypto_util import compute_hash

STORAGE_DIR = "Storage"


def ensure_storage():
    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)


def get_file_path(filename):
    return os.path.join(STORAGE_DIR, filename)


# The function that reads the file.

def read_file(filename):
    path = get_file_path(filename)

    if not os.path.exists(path):
        raise FileNotFoundError("File does not exist")

    with open(path, "rb") as f:
        return f.read()


def write_file(filename, data):
    path = get_file_path(filename)

    with open(path, "wb") as f:
        f.write(data)


def list_files():
    ensure_storage()
    return os.listdir(STORAGE_DIR)


def get_file_hash(filename):
    data = read_file(filename)
    return compute_hash(data)
