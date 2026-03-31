package crypto;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class CryptoUtils {

    public static SecretKey deriveSharedKey(
        PrivateKey privateKey, PublicKey publicKey) throws Exception {

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);

        byte[] sharedSecret = ka.generateSecret();

        // Simple key derivation (replace with HKDF ideally)
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }

    public static byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}