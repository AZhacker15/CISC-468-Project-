import os.path
import threading
import base64
import time

from network_file import NetworkPeer, send_json, recv_json
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
        message_type = data.get("type")

        if message_type == "PING":
            send_json(conn, {"type": "PONG"})

        elif message_type == "REQUEST_FILE_LIST":
            send_json(conn, {
                "type": "FILE_LIST",
                "files": list_files()
            })

        elif message_type == "SEND_FILE":
            self.handle_receive_file(conn, data)

        elif message_type == "REQUEST_FILE":
            self.handle_send_file(conn, data)

        elif message_type == "KEY_EXCHANGE":
            self.handle_key_exchange(conn, data)

        elif message_type == "KEY_EXCHANGE_REPLY":
            self.handle_key_exchange_reply(conn, data)

        elif message_type == "KEY_UPDATE":
            self.handle_key_update(conn, data)

        else:
            send_json(conn, {"type": "ERROR", "message": "Unknown request"})

    def rotate_keys(self):
        """
        Generate a new identity keypair and notify peers.
        """
        print("[KEY MIGRATION] Rotating identity keys...")

        self.private_key, self.public_key = generate_keypair()

        for conn in list(getattr(self, "connections", [])):
            try:
                send_json(conn, {
                    "type": "KEY_UPDATE",
                    "public_key": base64.b64encode(
                        serialize_public_key(self.public_key)
                    ).decode()
                })
            except Exception as e:
                print("[KEY MIGRATION ERROR]", e)

        print("[KEY MIGRATION] New keys active.")

    def handle_key_update(self, conn, data):
        try:
            new_key_bytes = base64.b64decode(data["public_key"])
            new_key = load_public_key(new_key_bytes)

            peer_addr = conn.getpeername()
            self.known_peers[peer_addr] = new_key

            print("[KEY UPDATE] Peer rotated identity key.")
        except Exception as e:
            print("[KEY UPDATE ERROR]", e)

    def handle_key_exchange(self, conn, data):
        try:
            peer_eph_bytes = base64.b64decode(data["eph_key"])
            peer_identity_bytes = base64.b64decode(data["identity_key"])
            signature = base64.b64decode(data["signature"])

            peer_identity_key = load_public_key(peer_identity_bytes)

            # verify peer identity signed their ephemeral key
            if not verify_signature(peer_identity_key, peer_eph_bytes, signature):
                send_json(conn, {"type": "ERROR", "message": "Auth failed"})
                conn.close()
                return

            peer_public = load_ephemeral_public(peer_eph_bytes)

            # generate our ephemeral key
            eph_private, eph_public = generate_ephemeral_keypair()

            conn.eph_private = eph_private

            session_key = derive_shared_key(eph_private, peer_public)
            conn.session_key = session_key

            send_json(conn, {
                "type": "KEY_EXCHANGE_REPLY",
                "eph_key": base64.b64encode(
                    serialize_ephemeral_public(eph_public)
                ).decode(),
                "identity_key": base64.b64encode(
                    serialize_public_key(self.public_key)
                ).decode(),
                "signature": base64.b64encode(
                    sign_data(self.private_key, serialize_ephemeral_public(eph_public))
                ).decode()
            })

        except Exception as e:
            print("[KEY_EXCHANGE ERROR]", e)

    def handle_key_exchange_reply(self, conn, data):
        try:
            peer_eph_bytes = base64.b64decode(data["eph_key"])

            peer_public = load_ephemeral_public(peer_eph_bytes)

            session_key = derive_shared_key(conn.eph_private, peer_public)
            setattr(conn, "session_key", session_key)

        except Exception as e:
            print("[KEY_EXCHANGE_REPLY ERROR]", e)

    def handle_receive_file(self, conn, data):
        file = data["filename"]

        user_choice = "y"  # I will implement a queue system later.

        if user_choice.lower() != 'y':
            send_json(conn, {"type": "ERROR", "message": "Rejected"})
            return

        session_key = getattr(conn, "session_key", None)
        if not session_key:
            print("ERROR No secure session established")
            return

        encrypted_data = base64.b64decode(data["data"])
        signature_data = base64.b64decode(data["signature"])

        peer_addr = conn.getpeername()
        peer_public_key = self.known_peers.get(peer_addr)

        if not peer_public_key:
            print("ERROR: Unknown peer (no identity key stored)")
            return

        plaintext = decrypt_data(session_key, encrypted_data)

        if compute_hash(plaintext) != data["hash"]:
            print("ERROR: File has been tampered.")
            return

        if not verify_signature(peer_public_key, plaintext, signature_data):
            print("ERROR: Signature is invalid.")
            return

        write_file(file + ".enc", encrypted_data)
        print(f"[FILE] {file} has been securely stored on storage.")

    def handle_send_file(self, conn, data):
        if not hasattr(conn, "session_key"):
            send_json(conn, {"type": "ERROR", "message": "No session"})
            return

        filename = data["filename"]

        try:
            file_data = read_file(filename)
        except:
            send_json(conn, {"type": "ERROR", "message": "File not found"})
            return

        encrypted = encrypt_data(conn.session_key, file_data)
        file_hash = compute_hash(file_data)
        signature = sign_data(self.private_key, file_data)

        send_json(conn, {
            "type": "SEND_FILE",
            "filename": filename,
            "data": base64.b64encode(encrypted).decode(),
            "hash": file_hash,
            "signature": base64.b64encode(signature).decode(),
            "public_key": base64.b64encode(
                serialize_public_key(self.public_key)
            ).decode()
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

            conn = peer.connect_to_peer(
                ip, peer.port, peer.private_key, peer.public_key
            )

            send_json(conn, {"type": "REQUEST_FILE_LIST"})

            response = recv_json(conn)
            if not response:
                print("[ERROR] No response from peer")
            else:
                print("\n[REMOTE FILE LIST]")
                print(response.get("files", response))

        elif choice == "3":
            ip = input("Peer IP: ")
            filename = input("Filename: ")

            conn = peer.connect_to_peer(
                ip, peer.port, peer.private_key, peer.public_key
            )
            time.sleep(1)

            send_json(conn, {
                "type": "REQUEST_FILE",
                "filename": filename
            })

            print("[INFO] File request sent... waiting for transfer")
            conn.settimeout(10)

            while True:
                try:
                    response = recv_json(conn)
                except:
                    print("[ERROR] User Timeout or disconnect")
                    break

                if not response:
                    break

                if response["type"] == "SEND_FILE":
                    print("[FILE RECEIVED]", response["filename"])
                    break

                elif response["type"] == "ERROR":
                    print("[SERVER ERROR]", response.get("message"))
                    break

        elif choice == "4":
            files = list_files()

            if not files:
                print("[LOCAL FILES] No files in Storage/")
            else:
                print("\n[LOCAL FILES]")
                for f in files:
                    path = get_file_path(f)
                    file_size = os.path.getsize(path)
                    print(f" -{f} ({file_size} bytes)")

        elif choice == "5":
            break


if __name__ == "__main__":
    main()
