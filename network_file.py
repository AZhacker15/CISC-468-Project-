import base64
import socket
import threading
import json
from crypto_util import generate_ephemeral_keypair, serialize_ephemeral_public, load_ephemeral_public, \
    derive_shared_key, load_public_key, verify_signature, sign_data, serialize_public_key

_conn_data = {}
_conn_data_lock = threading.Lock()

def get_session_data(conn):
    with _conn_data_lock:
        return _conn_data.get(id(conn))

def set_session_data(conn, data):
    with _conn_data_lock:
        _conn_data[id(conn)] = data
        print(f"[SESSION] Stored data for id={id(conn)}")

def del_session_data(conn):
    with _conn_data_lock:
        if id(conn) in _conn_data:
            del _conn_data[id(conn)]
            print(f"[SESSION] Removed data for id={id(conn)}")

def send_json(conn, data):
    try:
        message = json.dumps(data).encode()
        length = len(message)
        conn.sendall(length.to_bytes(4, 'big') + message)
    except Exception as e:
        print(f"[SEND ERROR] {e}")

def recv_json(conn):
    raw_length = recv_exact(conn, 4)
    if not raw_length:
        return None
    length = int.from_bytes(raw_length, 'big')
    data = recv_exact(conn, length)
    if not data:
        return None
    return json.loads(data.decode())

def recv_exact(conn, length):
    data = b""
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

def handle_client(conn, addr, peer):
    # Store empty session data for this connection
    set_session_data(conn, {})
    try:
        while True:
            data = recv_json(conn)
            if not data:
                break
            msg_type = data.get("type")
            print(f"[{addr}] {msg_type}")
            peer.handle_message(conn, data)
    except Exception as e:
        print(f"[HANDLE_CLIENT ERROR] {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
        del_session_data(conn)
        print(f"[DISCONNECTED] {addr}")

class NetworkPeer:
    def __init__(self, host="0.0.0.0", port=5001):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connections = []
        self.server.settimeout(1)
        self.lock = threading.Lock()

    def start_server(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"[LISTENING] on {self.host}:{self.port}")
        while True:
            try:
                conn, addr = self.server.accept()
                print(f"[NEW CONNECTION] {addr}")
                with self.lock:
                    self.connections.append(conn)
                thread = threading.Thread(target=handle_client, args=(conn, addr, self), daemon=True)
                thread.start()
            except socket.timeout:
                continue

    def connect_to_peer(self, peer_host, peer_port, private_key, public_key):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((peer_host, peer_port))
        set_session_data(client, {})

        with self.lock:
            self.connections.append(client)

        eph_private, eph_public = generate_ephemeral_keypair()
        session_data = get_session_data(client)
        session_data["eph_private"] = eph_private

        eph_pub_bytes = serialize_ephemeral_public(eph_public)
        signature = sign_data(private_key, eph_pub_bytes)
        send_json(client, {
            "type": "KEY_EXCHANGE",
            "eph_key": base64.b64encode(eph_pub_bytes).decode(),
            "identity_key": base64.b64encode(serialize_public_key(public_key)).decode(),
            "signature": base64.b64encode(signature).decode()
        })

        response = recv_json(client)
        if not response or response.get("type") != "KEY_EXCHANGE_REPLY":
            print("ERROR: Key exchange failed - unexpected reply")
            client.close()
            self.remove_connection(client)
            return None

        peer_eph_bytes = base64.b64decode(response["eph_key"])
        peer_identity_bytes = base64.b64decode(response["identity_key"])
        peer_signature = base64.b64decode(response["signature"])

        peer_identity_key = load_public_key(peer_identity_bytes)
        if not verify_signature(peer_identity_key, peer_eph_bytes, peer_signature):
            print("[SECURITY] Server authentication failed!")
            client.close()
            self.remove_connection(client)
            return None

        peer_public_key = load_ephemeral_public(peer_eph_bytes)
        session_key = derive_shared_key(eph_private, peer_public_key)
        session_data["session_key"] = session_key
        session_data["peer_identity_key"] = peer_identity_key

        print(f"[CONNECTED + AUTH + PFS] to {peer_host}:{peer_port}")
        return client

    def remove_connection(self, conn):
        with self.lock:
            if conn in self.connections:
                self.connections.remove(conn)
        del_session_data(conn)

    def close_all(self):
        for conn in self.connections:
            conn.close()
        self.server.close()