import crypto.KeyManager;
import network.PeerClient;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Paths;

public class MainClient {
    public static void main(String[] args) throws Exception {
        KeyManager km = new KeyManager();
        km.loadOrCreateKeys();
        System.out.println(Paths.get("shared").toAbsolutePath());
        PeerClient client = new PeerClient(km);
       // System.out.println("test1");
        client.connect("10.10.123.58", 5002);
        //System.out.println("test2");
        BufferedReader console = new BufferedReader(
                new InputStreamReader(System.in));

        while (true) {
            System.out.print("\nCommand (list/get <file>): ");
            String cmd = console.readLine();

            if (cmd.equals("list")) {
                client.requestFileList();
            }
            else if (cmd.startsWith("get ")) {
                client.requestFile(cmd.substring(4));
            }
        }

    }
}