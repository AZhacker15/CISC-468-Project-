rom zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import time

SERVICE_TYPE = "_p2pfileshare._tcp.local."


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't actually send data
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def register_service(port):
    zeroconf = Zeroconf()

    hostname = socket.gethostname()
    ip = get_local_ip()

    info = ServiceInfo(
        SERVICE_TYPE,
        f"{hostname}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties={},
    )

    zeroconf.register_service(info)
    print(f"[DISCOVERY] Advertising {ip}:{port}")

    return zeroconf, info


# Discover peers

class PeerListener:
    def __init__(self):
        self.peers = set()

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if not info:
            return

        ip = socket.inet_ntoa(info.addresses[0])
        port = info.port

        peer = (ip, port)

        if peer not in self.peers:
            self.peers.add(peer)
            print(f"[FOUND PEER] {ip}:{port}")

    # IMPORTANT FIX (removes warning)
    def update_service(self, zeroconf, type, name):
        self.add_service(zeroconf, type, name)

    def remove_service(self, zeroconf, type, name):
        pass


# =========================
# DISCOVER PEERS
# =========================
def discover_peers(timeout=5):
    zeroconf = Zeroconf()
    listener = PeerListener()

    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    print("[DISCOVERY] Searching for peers...")
    time.sleep(timeout)

    zeroconf.close()

    return list(listener.peers)

