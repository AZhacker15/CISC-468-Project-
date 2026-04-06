import os
from crypto_util import compute_hash, decrypt_data, generate_aes_key

STORAGE_DIR = "Storage"


def ensure_storage():
    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)


def get_file_path(filename):
    filename = os.path.basename(filename)
    return os.path.join(STORAGE_DIR, filename)


# The function that reads the file.

def load_local_key():
    if not os.path.exists("local.key"):
        with open("local.key", "wb") as f:
            f.write(generate_aes_key())

    with open("local.key", "rb") as f:
        return f.read()


def read_file(filename):
    path = get_file_path(filename)

    if not os.path.exists(path):
        raise FileNotFoundError("File does not exist")

    with open(path, "rb") as f:
        encrypted_data = f.read()

    local_key = load_local_key()  # you need this helper
    return decrypt_data(local_key, encrypted_data)


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

