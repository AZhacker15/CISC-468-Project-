package network;

import java.net.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import file.FileManager;
import org.json.*;

import crypto.*;

public class PeerServer implements Runnable {

    private int port;
    private KeyManager keyManager;

    public PeerServer(int port, KeyManager keyManager) {
        this.port = port;
        this.keyManager = keyManager;
    }

    class PeerSession {
        public PublicKey peerPublicKey;
        public SecretKey sessionKey;
        public boolean authenticated = false;
    }


    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("PeerServer running on port " + port);

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> handleClient(socket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket socket) {
        PeerSession session = new PeerSession();

        try {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream()));

            String line;
            while ((line = in.readLine()) != null) {
                Message msg = Message.fromJSON(line);
                handleMessage(msg, out, session);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleMessage(Message msg, BufferedWriter out, PeerSession session) throws Exception {

        switch (msg.type) {

            case HELLO:
                System.out.println("Received HELLO");

                byte[] peerKeyBytes = Base64.getDecoder()
                        .decode(msg.payload.getString("publicKey"));

                KeyFactory kf = KeyFactory.getInstance("EC");
                session.peerPublicKey = kf.generatePublic(
                        new X509EncodedKeySpec(peerKeyBytes));

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                KeyPair ephemeral = kpg.generateKeyPair();

                session.sessionKey = CryptoUtils.deriveSharedKey(
                        ephemeral.getPrivate(),
                        session.peerPublicKey);

                JSONObject payload = new JSONObject();
                payload.put("publicKey", Base64.getEncoder()
                        .encodeToString(ephemeral.getPublic().getEncoded()));

                send(out, new Message(MessageType.AUTH, payload));
                break;

            case AUTH:
                System.out.println("Received AUTH");

                byte[] challenge = Base64.getDecoder()
                        .decode(msg.payload.getString("challenge"));
                byte[] signature = Base64.getDecoder()
                        .decode(msg.payload.getString("signature"));

                boolean valid = SignatureUtils.verify(
                        session.peerPublicKey,
                        challenge,
                        signature);

                if (!valid) {
                    sendError(out, "Authentication failed");
                    return;
                }

                session.authenticated = true;
                System.out.println("Peer authenticated!");
                break;

            case FILE_LIST:
                JSONArray files = new JSONArray();

                Files.list(Paths.get("shared")).forEach(path -> {
                    try {
                        byte[] data = FileManager.readFile(path.toString());
                        String hash = FileManager.computeHash(data);

                        JSONObject obj = new JSONObject();
                        obj.put("filename", path.getFileName().toString());
                        obj.put("hash", hash);

                        files.put(obj);
                    } catch (Exception ignored) {}
                });

                JSONObject listPayload = new JSONObject();
                listPayload.put("files", files);

                send(out, new Message(MessageType.FILE_LIST, listPayload));
                break;

            case FILE_REQUEST:
                if (!session.authenticated) {
                    sendError(out, "Not authenticated");
                    return;
                }

                String filename = msg.payload.getString("filename");

                System.out.println("Send file " + filename + "? (y/n)");
                BufferedReader console = new BufferedReader(
                        new InputStreamReader(System.in));

                if (!console.readLine().equalsIgnoreCase("y")) {
                    sendError(out, "User denied request");
                    return;
                }

                sendFile(out, filename, session);
                break;

            case FILE_TRANSFER:
                byte[] encrypted = Base64.getDecoder()
                        .decode(msg.payload.getString("data"));
                byte[] iv = Base64.getDecoder()
                        .decode(msg.payload.getString("iv"));
                String hash = msg.payload.getString("hash");
                byte[] sig = Base64.getDecoder()
                        .decode(msg.payload.getString("signature"));

                byte[] decrypted = decrypt(session.sessionKey, encrypted, iv);

                String computedHash = FileManager.computeHash(decrypted);

                if (!computedHash.equals(hash)) {
                    sendError(out, "File corrupted");
                    return;
                }

                boolean sigValid = SignatureUtils.verify(
                        session.peerPublicKey,
                        hash.getBytes(),
                        sig);

                if (!sigValid) {
                    sendError(out, "Invalid signature");
                    return;
                }

                Files.createDirectories(Paths.get("downloads"));
                Files.write(Paths.get("downloads/" +
                        msg.payload.getString("filename")), decrypted);

                System.out.println("File received securely!");
                break;

            default:
                sendError(out, "Unknown message type");
        }
    }


    private void sendFile(BufferedWriter out, String filename, PeerSession session) throws Exception {

        byte[] data = FileManager.readFile("Shared/" + filename);
        String hash = FileManager.computeHash(data);

        byte[] signature = SignatureUtils.sign(
                keyManager.getPrivateKey(),
                hash.getBytes());

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, session.sessionKey);

        byte[] encrypted = cipher.doFinal(data);
        byte[] iv = cipher.getIV();

        JSONObject payload = new JSONObject();
        payload.put("filename", filename);
        payload.put("data", Base64.getEncoder().encodeToString(encrypted));
        payload.put("iv", Base64.getEncoder().encodeToString(iv));
        payload.put("hash", hash);
        payload.put("signature", Base64.getEncoder().encodeToString(signature));

        send(out, new Message(MessageType.FILE_TRANSFER, payload));
    }

    private byte[] decrypt(SecretKey key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }


    private void send(BufferedWriter out, Message msg) throws Exception {
        out.write(msg.toJSON());
        out.newLine();
        out.flush();
    }

    private void sendError(BufferedWriter out, String error) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("error", error);

        send(out, new Message(MessageType.ERROR, payload));
    }
}