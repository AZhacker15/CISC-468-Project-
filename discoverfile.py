from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import time

SERVICE_TYPE = "_p2pfileshare._tcp.local."


def register_service(port):
    zeroconf = Zeroconf()

    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)

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
        self.peers = []

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port

            peer = (ip, port)
            if peer not in self.peers:
                self.peers.append(peer)
                print(f"[FOUND PEER] {ip}:{port}")

    def remove_service(self, zeroconf, type, name):
        pass  # optional


def discover_peers(timeout=5):
    zeroconf = Zeroconf()
    listener = PeerListener()

    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    print("[DISCOVERY] Searching for peers...")
    time.sleep(timeout)

    zeroconf.close()

    return listener.peers
