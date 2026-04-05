package crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils {

    public static KeyPair generateX25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        return kpg.generateKeyPair();
    }

    public static byte[] getRawX25519PublicKey(PublicKey pubKey) {
        byte[] encoded = pubKey.getEncoded();
        if (encoded.length != 44) {
            throw new RuntimeException("Unexpected X25519 public key length: " + encoded.length);
        }
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    public static PublicKey decodeX25519PublicKey(byte[] raw) throws Exception {
        byte[] prefix = {
                0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00
        };
        byte[] encoded = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, encoded, 0, prefix.length);
        System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static byte[] x25519SharedSecret(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    public static KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }

    public static byte[] getRawEd25519PublicKey(PublicKey pubKey) {
        byte[] encoded = pubKey.getEncoded();
        if (encoded.length != 44) {
            throw new RuntimeException("Unexpected Ed25519 public key length: " + encoded.length);
        }
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    public static PublicKey decodeEd25519PublicKey(byte[] raw) throws Exception {
        byte[] prefix = {
                0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
        };
        byte[] encoded = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, encoded, 0, prefix.length);
        System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static byte[] signEd25519(PrivateKey privateKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verifyEd25519(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    public static byte[] hkdf(byte[] ikm, String info, int length) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        byte[] salt = new byte[32];
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        hmac.init(saltKey);
        byte[] prk = hmac.doFinal(ikm);

        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        int n = (length + 31) / 32;
        for (int i = 1; i <= n; i++) {
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            hmac.update(t);
            hmac.update(info.getBytes(StandardCharsets.UTF_8));
            hmac.update((byte) i);
            t = hmac.doFinal();
            System.arraycopy(t, 0, result, pos, Math.min(t.length, length - pos));
            pos += t.length;
        }
        return result;
    }

    public static byte[] encryptAESGCM(SecretKey key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    public static byte[] decryptAESGCM(SecretKey key, byte[] encrypted) throws Exception {
        if (encrypted.length < 12) throw new IllegalArgumentException();
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[encrypted.length - 12];
        System.arraycopy(encrypted, 0, iv, 0, 12);
        System.arraycopy(encrypted, 12, ciphertext, 0, ciphertext.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(ciphertext);
    }
}