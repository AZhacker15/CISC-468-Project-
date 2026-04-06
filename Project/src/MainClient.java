import crypto.KeyManager;
import network.PeerClient;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class MainClient {
    public static void main(String[] args) throws Exception {
        KeyManager km = new KeyManager();
        km.loadOrCreateKeys();
        PeerClient client = new PeerClient(km);
        client.connect("172.20.10.5", 5001);
        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.print("\nCommand (list/get <file>): ");
            String cmd = console.readLine();
            if (cmd.equals("list")) {
                client.requestFileList();
            } else if (cmd.startsWith("get ")) {
                client.requestFile(cmd.substring(4));
            }
        }
    }
}