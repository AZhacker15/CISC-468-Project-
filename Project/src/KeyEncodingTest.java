import crypto.CryptoUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class KeyEncodingTest {

    @Test
    public void testEd25519RawEncoding() throws Exception {
        KeyPair kp = CryptoUtils.generateEd25519KeyPair();

        byte[] raw = CryptoUtils.getRawEd25519PublicKey(kp.getPublic());
        PublicKey reconstructed = CryptoUtils.decodeEd25519PublicKey(raw);

        assertArrayEquals(
                kp.getPublic().getEncoded(),
                reconstructed.getEncoded(),
                "Reconstructed key must match original"
        );
    }

    @Test
    public void testX25519RawEncoding() throws Exception {
        KeyPair kp = CryptoUtils.generateX25519KeyPair();

        byte[] raw = CryptoUtils.getRawX25519PublicKey(kp.getPublic());
        PublicKey reconstructed = CryptoUtils.decodeX25519PublicKey(raw);

        assertArrayEquals(
                kp.getPublic().getEncoded(),
                reconstructed.getEncoded()
        );
    }
}