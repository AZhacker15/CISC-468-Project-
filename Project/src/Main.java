import crypto.KeyManager;
import discovery.MDNSService;
import network.PeerServer;

public class Main {
    public static void main(String[] args) throws Exception {
        KeyManager keyManager = new KeyManager();
        keyManager.loadOrCreateKeys();

        PeerServer server = new PeerServer(5001, keyManager);
        new Thread(server).start();

        MDNSService discovery = new MDNSService(5001);

        discovery.registerService();
        discovery.discoverPeers();

        System.out.println("Peer started...");
    }
}