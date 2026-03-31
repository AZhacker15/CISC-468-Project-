package network;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.SecretKey;
import file.FileManager;

import org.json.JSONObject;

import crypto.*;

public class PeerClient {

    private Socket socket;
    private BufferedReader in;
    private BufferedWriter out;

    private KeyManager keyManager;

    private PublicKey peerPublicKey;
    private SecretKey sessionKey;
    private boolean authenticated = false;

    public PeerClient(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    // =========================
    // CONNECT TO PEER
    // =========================
    public void connect(String host, int port) throws Exception {
        socket = new Socket(host, port);

        in = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));
        out = new BufferedWriter(
                new OutputStreamWriter(socket.getOutputStream()));

        System.out.println("Connected to peer");

        sendHello();

        // Start listener thread
        new Thread(this::listen).start();
    }

    // =========================
    // SEND HELLO
    // =========================
    private void sendHello() throws Exception {
        JSONObject payload = new JSONObject();

        payload.put("publicKey", Base64.getEncoder()
                .encodeToString(keyManager.getPublicKey().getEncoded()));

        send(new Message(MessageType.HELLO, payload));
    }

    // =========================
    // LISTEN FOR RESPONSES
    // =========================
    private void listen() {
        try {
            String line;

            while ((line = in.readLine()) != null) {
                Message msg = Message.fromJSON(line);
                handleMessage(msg);
            }

        } catch (Exception e) {
            System.out.println("Connection closed.");
        }
    }

    // =========================
    // HANDLE MESSAGES
    // =========================
    private void handleMessage(Message msg) throws Exception {

        switch (msg.type) {

            // =========================
            // AUTH RESPONSE FROM SERVER
            // =========================
            case AUTH:
                System.out.println("Received AUTH");

                byte[] peerKeyBytes = Base64.getDecoder()
                        .decode(msg.payload.getString("publicKey"));

                KeyFactory kf = KeyFactory.getInstance("EC");
                peerPublicKey = kf.generatePublic(
                        new X509EncodedKeySpec(peerKeyBytes));

                // Derive session key
                sessionKey = CryptoUtils.deriveSharedKey(
                        keyManager.getPrivateKey(),
                        peerPublicKey);

                System.out.println("Session key established");

                // Send challenge
                byte[] challenge = new byte[32];
                new SecureRandom().nextBytes(challenge);

                byte[] signature = SignatureUtils.sign(
                        keyManager.getPrivateKey(), challenge);

                JSONObject payload = new JSONObject();
                payload.put("challenge", Base64.getEncoder()
                        .encodeToString(challenge));
                payload.put("signature", Base64.getEncoder()
                        .encodeToString(signature));

                send(new Message(MessageType.AUTH, payload));
                break;

            // =========================
            // FILE LIST
            // =========================
            case FILE_LIST:
                System.out.println("\nAvailable files:");

                for (Object o : msg.payload.getJSONArray("files")) {
                    JSONObject f = (JSONObject) o;
                    System.out.println("- " + f.getString("filename"));
                }
                break;

            // =========================
            // FILE TRANSFER
            // =========================
            case FILE_TRANSFER:
                handleFileTransfer(msg.payload);
                break;

            case ERROR:
                System.out.println("Error: " +
                        msg.payload.getString("error"));
                break;

            default:
                System.out.println("Unknown message");
        }
    }

    // =========================
    // HANDLE FILE
    // =========================
    private void handleFileTransfer(JSONObject payload) throws Exception {

        byte[] encrypted = Base64.getDecoder()
                .decode(payload.getString("data"));

        byte[] iv = Base64.getDecoder()
                .decode(payload.getString("iv"));

        String hash = payload.getString("hash");

        byte[] signature = Base64.getDecoder()
                .decode(payload.getString("signature"));

        byte[] decrypted = decrypt(sessionKey, encrypted, iv);

        String computedHash = FileManager.computeHash(decrypted);

        if (!computedHash.equals(hash)) {
            System.out.println("File corrupted!");
            return;
        }

        boolean valid = SignatureUtils.verify(
                peerPublicKey,
                hash.getBytes(),
                signature);

        if (!valid) {
            System.out.println("Invalid signature!");
            return;
        }

        new File("downloads").mkdirs();
        FileOutputStream fos = new FileOutputStream(
                "downloads/" + payload.getString("filename"));

        fos.write(decrypted);
        fos.close();

        System.out.println("File downloaded securely!");
    }

    // =========================
    // REQUEST FILE LIST
    // =========================
    public void requestFileList() throws Exception {
        send(new Message(MessageType.FILE_LIST, new JSONObject()));
    }

    // =========================
    // REQUEST FILE
    // =========================
    public void requestFile(String filename) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("filename", filename);

        send(new Message(MessageType.FILE_REQUEST, payload));
    }

    // =========================
    // SEND MESSAGE
    // =========================
    private void send(Message msg) throws Exception {
        out.write(msg.toJSON());
        out.newLine();
        out.flush();
    }

    // =========================
    // DECRYPT
    // =========================
    private byte[] decrypt(SecretKey key, byte[] data, byte[] iv) throws Exception {
        javax.crypto.Cipher cipher =
                javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");

        javax.crypto.spec.GCMParameterSpec spec =
                new javax.crypto.spec.GCMParameterSpec(128, iv);

        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }
}