import os.path
import threading
import base64
import time

from network_file import NetworkPeer, send_json, recv_json, get_session_data
from crypto_util import (
    generate_keypair, sign_data, verify_signature,
    encrypt_data, decrypt_data,
    serialize_public_key, load_public_key, compute_hash, load_ephemeral_public, generate_ephemeral_keypair,
    derive_shared_key, serialize_ephemeral_public
)
from file_util import (
    read_file, write_file, list_files, ensure_storage, get_file_path
)
from discoverfile import register_service, discover_peers


class securePeer(NetworkPeer):
    def __init__(self, host="0.0.0.0", port=5001):
        super().__init__(host, port)
        self.private_key, self.public_key = generate_keypair()
        self.known_peers = {}

    def handle_message(self, conn, data):
        print("test")
        conn_info = get_session_data(conn)
        print("test2")
        print(f"[DEBUG] handle_message: conn id={id(conn)}, conn_info={conn_info is not None}")
        if conn_info is None:
            send_json(conn, {"type": "ERROR", "message": "Internal error"})
            return
        print("test3")
        msg_type = data.get("type")
        if msg_type != "KEY_EXCHANGE":
            if "session_key" not in conn_info or "peer_identity_key" not in conn_info:
                send_json(conn, {"type": "ERROR", "message": "Not authenticated"})
                return

        if msg_type == "PING":
            send_json(conn, {"type": "PONG"})
        elif msg_type == "REQUEST_FILE_LIST":
            send_json(conn, {"type": "FILE_LIST", "files": list_files()})
        elif msg_type == "REQUEST_FILE":
            self.handle_send_file(conn, data)
        elif msg_type == "SEND_FILE":
            self.handle_receive_file(conn, data)
        elif msg_type == "KEY_EXCHANGE":
            self.handle_key_exchange(conn, data)
        else:
            send_json(conn, {"type": "ERROR", "message": "Unknown request"})

    def handle_key_exchange(self, conn, data):
        try:
            print("[KEY_EXCHANGE] Starting")

            conn_info = get_session_data(conn)
            if conn_info is None:
                raise RuntimeError("No session data")
            peer_eph_bytes = base64.b64decode(data["eph_key"])
            peer_identity_bytes = base64.b64decode(data["identity_key"])
            signature = base64.b64decode(data["signature"])
            print(f"[DEBUG] eph len: {len(peer_eph_bytes)}")
            print(f"[DEBUG] id len: {len(peer_identity_bytes)}")

            if len(peer_eph_bytes) != 32 or len(peer_identity_bytes) != 32:
                send_json(conn, {"type": "ERROR", "message": "Invalid key length"})
                return

            peer_identity_key = load_public_key(peer_identity_bytes)
            if not verify_signature(peer_identity_key, peer_eph_bytes, signature):
                send_json(conn, {"type": "ERROR", "message": "Authentication failed"})
                return

            eph_private, eph_public = generate_ephemeral_keypair()
            peer_ephemeral = load_ephemeral_public(peer_eph_bytes)
            session_key = derive_shared_key(eph_private, peer_ephemeral)

            conn_info["peer_identity_key"] = peer_identity_key
            conn_info["session_key"] = session_key

            our_eph_pub = serialize_ephemeral_public(eph_public)
            our_signature = sign_data(self.private_key, our_eph_pub)

            send_json(conn, {
                "type": "KEY_EXCHANGE_REPLY",
                "eph_key": base64.b64encode(our_eph_pub).decode(),
                "identity_key": base64.b64encode(serialize_public_key(self.public_key)).decode(),
                "signature": base64.b64encode(our_signature).decode()
            })

            print("[KEY_EXCHANGE] Success")

        except Exception as e:
            print(f"[KEY_EXCHANGE ERROR] {e}")
            import traceback
            traceback.print_exc()
            send_json(conn, {"type": "ERROR", "message": f"Key exchange failed: {str(e)}"})
            conn.close()
    def handle_receive_file(self, conn, data):
        conn_info = get_session_data(conn)
        if not conn_info or "session_key" not in conn_info or "peer_identity_key" not in conn_info:
            send_json(conn, {"type": "ERROR", "message": "No secure session"})
            return

        session_key = conn_info["session_key"]
        peer_public_key = conn_info["peer_identity_key"]

        filename = data["filename"]
        user_choice = "y"

        if user_choice.lower() != 'y':
            send_json(conn, {"type": "ERROR", "message": "Rejected"})
            return

        encrypted_data = base64.b64decode(data["data"])
        signature_data = base64.b64decode(data["signature"])

        plaintext = decrypt_data(session_key, encrypted_data)

        if compute_hash(plaintext) != data["hash"]:
            print("ERROR: File hash mismatch")
            return

        if not verify_signature(peer_public_key, plaintext, signature_data):
            print("ERROR: Invalid signature")
            return

        write_file(filename + ".enc", encrypted_data)
        print(f"[FILE] Received {filename} securely")

    def handle_send_file(self, conn, data):
        conn_info = get_session_data(conn)
        if not conn_info or "session_key" not in conn_info:
            send_json(conn, {"type": "ERROR", "message": "No session"})
            return

        session_key = conn_info["session_key"]
        filename = data["filename"]

        try:
            file_data = read_file(filename)
        except FileNotFoundError:
            send_json(conn, {"type": "ERROR", "message": "File not found"})
            return

        encrypted = encrypt_data(session_key, file_data)
        file_hash = compute_hash(file_data)
        signature = sign_data(self.private_key, file_data)

        send_json(conn, {
            "type": "SEND_FILE",
            "filename": filename,
            "data": base64.b64encode(encrypted).decode(),
            "hash": file_hash,
            "signature": base64.b64encode(signature).decode(),
            "public_key": base64.b64encode(serialize_public_key(self.public_key)).decode()
        })


def main():
    ensure_storage()
    peer = securePeer()
    threading.Thread(target=peer.start_server, daemon=True).start()
    register_service(peer.port)

    while True:
        print("\n1. Discover Existing Peers")
        print("2. Request File List")
        print("3. Request File")
        print("4. View Local Files")
        print("5. Exit")
        choice = input("> ")

        if choice == "1":
            print(discover_peers())
        elif choice == "2":
            ip = input("Peer IP: ")
            conn = peer.connect_to_peer(ip, peer.port, peer.private_key, peer.public_key)
            if not conn:
                print("Connection failed")
                continue
            send_json(conn, {"type": "REQUEST_FILE_LIST"})
            response = recv_json(conn)
            if response:
                print("\n[REMOTE FILE LIST]")
                print(response.get("files", response))
            conn.close()
        elif choice == "3":
            ip = input("Peer IP: ")
            filename = input("Filename: ")
            conn = peer.connect_to_peer(ip, peer.port, peer.private_key, peer.public_key)
            if not conn:
                print("Connection failed")
                continue
            send_json(conn, {"type": "REQUEST_FILE", "filename": filename})
            conn.settimeout(10)
            try:
                response = recv_json(conn)
                if response and response.get("type") == "SEND_FILE":
                    print(f"[FILE RECEIVED] {response['filename']}")
                elif response and response.get("type") == "ERROR":
                    print(f"[ERROR] {response.get('message')}")
            except Exception as e:
                print(f"Error: {e}")
            conn.close()
        elif choice == "4":
            files = list_files()
            if not files:
                print("[LOCAL FILES] No files in Storage/")
            else:
                print("\n[LOCAL FILES]")
                for f in files:
                    path = get_file_path(f)
                    size = os.path.getsize(path)
                    print(f" - {f} ({size} bytes)")
        elif choice == "5":
            break


if __name__ == "__main__":
    main()