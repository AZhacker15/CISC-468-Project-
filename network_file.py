import socket
import threading
import json

BUFFER_SIZE = 4096


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
    try:
        while True:
            data = recv_json(conn)
            if not data:
                break

            msg_type = data.get("type")
            print(f"[{addr}] {msg_type}")

            peer.handle_message(conn, data)

    except Exception as e:
        print(f"[ERROR] {e}")

    finally:
        conn.close()
        peer.remove_connection(conn)
        print(f"[DISCONNECTED] {addr}")


def send_message(conn, data):
    send_json(conn, data)


class NetworkPeer:
    def __init__(self, host="0.0.0.0", port=5000):
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

                thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, self),  # <-- pass the NetworkPeer instance
                    daemon=True
                )
                thread.start()

            except socket.timeout:
                continue  # just keep listening

    def connect_to_peer(self, peer_host, peer_port):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((peer_host, peer_port))
        with self.lock:
            self.connections.append(client)
        print(f"[CONNECTED] to {peer_host}:{peer_port}")
        return client

    def remove_connection(self, conn):
        with self.lock:
            if conn in self.connections:
                self.connections.remove(conn)

    def close_all(self):
        for conn in self.connections:
            conn.close()
        self.server.close()
