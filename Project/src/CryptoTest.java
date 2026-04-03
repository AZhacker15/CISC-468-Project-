import crypto.CryptoUtils;
import crypto.KeyManager;
import crypto.SignatureUtils;
import file.FileManager;

import javax.crypto.SecretKey;

public class CryptoTest {
    public static void main(String[] args) throws Exception {
        KeyManager km1 = new KeyManager();
        km1.loadOrCreateKeys();

        KeyManager km2 = new KeyManager();
        km2.loadOrCreateKeys();

        SecretKey key1 = CryptoUtils.deriveSharedKey(
                km1.getPrivateKey(), km2.getPublicKey());

        SecretKey key2 = CryptoUtils.deriveSharedKey(
                km2.getPrivateKey(), km1.getPublicKey());

        System.out.println("Keys match: " +
                java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()));

        byte[] data = "hello".getBytes();

        byte[] sig = SignatureUtils.sign(km1.getPrivateKey(), data);

        boolean valid = SignatureUtils.verify(
                km1.getPublicKey(), data, sig);

        System.out.println("Signature valid: " + valid);

        byte[] data2 = "test".getBytes();
        String hash1 = FileManager.computeHash(data2);
        String hash2 = FileManager.computeHash(data2);

        System.out.println(hash1.equals(hash2));
    }
}