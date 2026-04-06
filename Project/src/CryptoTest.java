import crypto.CryptoUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoTest {

    @Test
    public void testEd25519SignVerify() throws Exception {
        KeyPair kp = CryptoUtils.generateEd25519KeyPair();
        byte[] message = "hello world".getBytes();

        byte[] sig = CryptoUtils.signEd25519(kp.getPrivate(), message);
        boolean valid = CryptoUtils.verifyEd25519(kp.getPublic(), message, sig);

        assertTrue(valid, "Signature should be valid");
    }

    @Test
    public void testEd25519TamperedMessage() throws Exception {
        KeyPair kp = CryptoUtils.generateEd25519KeyPair();
        byte[] message = "hello".getBytes();

        byte[] sig = CryptoUtils.signEd25519(kp.getPrivate(), message);

        message[0] ^= 1; // tamper

        boolean valid = CryptoUtils.verifyEd25519(kp.getPublic(), message, sig);
        assertFalse(valid, "Tampered message should fail verification");
    }

    @Test
    public void testX25519SharedSecret() throws Exception {
        KeyPair a = CryptoUtils.generateX25519KeyPair();
        KeyPair b = CryptoUtils.generateX25519KeyPair();

        byte[] s1 = CryptoUtils.x25519SharedSecret(a.getPrivate(), b.getPublic());
        byte[] s2 = CryptoUtils.x25519SharedSecret(b.getPrivate(), a.getPublic());

        assertArrayEquals(s1, s2, "Shared secrets must match");
    }

    @Test
    public void testHKDFConsistency() throws Exception {
        byte[] input = "shared-secret".getBytes();

        byte[] k1 = CryptoUtils.hkdf(input, "test", 32);
        byte[] k2 = CryptoUtils.hkdf(input, "test", 32);

        assertArrayEquals(k1, k2, "HKDF output must be deterministic");
    }

    @Test
    public void testAESGCMEncryptDecrypt() throws Exception {
        byte[] keyBytes = new byte[32];
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] plaintext = "secret file data".getBytes();

        byte[] encrypted = CryptoUtils.encryptAESGCM(key, plaintext);
        byte[] decrypted = CryptoUtils.decryptAESGCM(key, encrypted);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testAESGCMTamperFails() throws Exception {
        byte[] keyBytes = new byte[32];
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] plaintext = "important".getBytes();
        byte[] encrypted = CryptoUtils.encryptAESGCM(key, plaintext);

        encrypted[encrypted.length - 1] ^= 1;

        assertThrows(Exception.class, () ->
                CryptoUtils.decryptAESGCM(key, encrypted)
        );
    }
}