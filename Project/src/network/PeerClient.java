package network;

import crypto.CryptoUtils;
import crypto.KeyManager;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import org.json.JSONObject;
import org.json.JSONArray;

public class PeerClient {
    private Socket socket;
    private InputStream in;
    private OutputStream out;
    private KeyManager keyManager;
    private SecretKey sessionKey;
    private PublicKey peerIdentityKey;

    public PeerClient(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public void connect(String host, int port) throws Exception {
        socket = new Socket(host, port);
        in = socket.getInputStream();
        out = socket.getOutputStream();
        System.out.println("Connected to " + host + ":" + port);

        performKeyExchange();
        new Thread(this::listen).start();
    }

    private void performKeyExchange() throws Exception {
        System.out.println("Sending KEY_EXCHANGE");


        KeyPair ephemeral = CryptoUtils.generateX25519KeyPair();
        byte[] rawEphPub = CryptoUtils.getRawX25519PublicKey(ephemeral.getPublic());
        System.out.println("Identity key length: " + keyManager.getRawPublicKey().length);
        System.out.println("Ephemeral key length: " + rawEphPub.length);
        byte[] signature = CryptoUtils.signEd25519(keyManager.getPrivateKey(), rawEphPub);

        JSONObject fields = new JSONObject();
        fields.put("eph_key", Base64.getEncoder().encodeToString(rawEphPub));
        fields.put("identity_key", Base64.getEncoder().encodeToString(keyManager.getRawPublicKey()));
        fields.put("signature", Base64.getEncoder().encodeToString(signature));
        send(new Message("KEY_EXCHANGE", fields));

        Message reply = Message.readFromStream(in);
        System.out.println("Received: " + reply.type);
        if ("ERROR".equals(reply.type)) {
            throw new RuntimeException("Peer rejected key exchange: " + reply.fields.getString("message"));
        }
        if (!"KEY_EXCHANGE_REPLY".equals(reply.type)) {
            throw new RuntimeException("Expected KEY_EXCHANGE_REPLY, got " + reply.type);
        }

        byte[] peerRawEphPub = Base64.getDecoder().decode(reply.fields.getString("eph_key"));
        byte[] peerRawIdPub = Base64.getDecoder().decode(reply.fields.getString("identity_key"));
        byte[] peerSig = Base64.getDecoder().decode(reply.fields.getString("signature"));

        PublicKey peerIdKey = CryptoUtils.decodeEd25519PublicKey(peerRawIdPub);
        boolean valid = CryptoUtils.verifyEd25519(peerIdKey, peerRawEphPub, peerSig);
        if (!valid) throw new SecurityException("Peer authentication failed – invalid signature");

        PublicKey peerEphPublic = CryptoUtils.decodeX25519PublicKey(peerRawEphPub);
        byte[] sharedSecret = CryptoUtils.x25519SharedSecret(ephemeral.getPrivate(), peerEphPublic);
        byte[] sessionKeyBytes = CryptoUtils.hkdf(sharedSecret, "p2p-file-transfer", 32);
        sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
        peerIdentityKey = peerIdKey;

        System.out.println("Secure session established");
    }


    private void listen() {
        try {
            while (true) {
                Message msg = Message.readFromStream(in);
                handleMessage(msg);
            }
        } catch (EOFException e) {
            System.out.println("Connection closed by peer");
        } catch (Exception e) {
            System.err.println("Listener error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleMessage(Message msg) throws Exception {
        switch (msg.type) {
            case "FILE_LIST":
                JSONArray files = msg.fields.getJSONArray("files");
                System.out.println("\nAvailable files:");
                for (int i = 0; i < files.length(); i++) {
                    System.out.println("- " + files.getString(i));
                }
                break;
            case "SEND_FILE":
                receiveFile(msg.fields);
                break;
            case "ERROR":
                System.err.println("Peer error: " + msg.fields.getString("message"));
                break;
            default:
                System.out.println("Unhandled message type: " + msg.type);
        }
    }

    private void receiveFile(JSONObject fields) throws Exception {
        String filename = fields.getString("filename");
        byte[] encryptedData = Base64.getDecoder().decode(fields.getString("data"));
        String expectedHash = fields.getString("hash");
        byte[] signature = Base64.getDecoder().decode(fields.getString("signature"));
        byte[] pubKeyBytes = Base64.getDecoder().decode(fields.getString("public_key"));

        PublicKey senderPub = CryptoUtils.decodeEd25519PublicKey(pubKeyBytes);
        if (!senderPub.equals(peerIdentityKey)) {
            System.err.println("Warning: file sender identity key differs from key exchange peer");
        }

        byte[] plaintext = CryptoUtils.decryptAESGCM(sessionKey, encryptedData);

        String computedHash = bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(plaintext));
        if (!computedHash.equals(expectedHash)) {
            System.err.println("File hash mismatch – possible corruption");
            return;
        }

        boolean valid = CryptoUtils.verifyEd25519(senderPub, plaintext, signature);
        if (!valid) {
            System.err.println("Invalid signature – file authenticity check failed");
            return;
        }

        new File("downloads").mkdirs();
        try (FileOutputStream fos = new FileOutputStream("downloads/" + filename)) {
            fos.write(plaintext);
        }
        System.out.println("File '" + filename + "' downloaded and verified successfully.");
    }

    public void requestFileList() throws Exception {
        send(new Message("REQUEST_FILE_LIST", new JSONObject()));
    }

    public void requestFile(String filename) throws Exception {
        JSONObject fields = new JSONObject();
        fields.put("filename", filename);
        send(new Message("REQUEST_FILE", fields));
    }

    private void send(Message msg) throws Exception {
        out.write(msg.toBytes());
        out.flush();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}