import threading
import base64

from network_file import NetworkPeer, send_json
from crypto_util import (
    generate_keypair, sign_data, verify_signature,
    encrypt_data, decrypt_data,
    serialize_public_key, load_public_key, compute_hash
)
from file_util import (
    read_file, write_file, list_files, ensure_storage
)
from discoverfile import register_service, discover_peers


class securePeer(NetworkPeer):
    def __init__(self, host="0,0,0,0", port=5001):
        super().__init__(host, port)

        self.private_key, self.public_key = generate_keypair()
        self.known_peers = {}

        