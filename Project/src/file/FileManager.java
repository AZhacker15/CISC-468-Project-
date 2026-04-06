package file;

import java.nio.file.*;
import java.security.*;

public class FileManager {

    public static byte[] readFile(String path) throws Exception {
        return Files.readAllBytes(Paths.get(path));
    }

    public static String computeHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}