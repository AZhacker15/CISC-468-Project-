package network;
import java.net.*;
import java.io.*;

public class PeerClient {

    public static void sendMessage(String host, int port, Message msg) throws Exception {
        Socket socket = new Socket(host, port);

        BufferedWriter out = new BufferedWriter(
            new OutputStreamWriter(socket.getOutputStream()));

        out.write(msg.toJSON());
        out.newLine();
        out.flush();

        socket.close();
    }
}