import crypto.CryptoUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class HandshakeTest {

    @Test
    public void testFullKeyExchange() throws Exception {
        KeyPair aliceId = CryptoUtils.generateEd25519KeyPair();
        KeyPair bobId = CryptoUtils.generateEd25519KeyPair();

        KeyPair aliceEph = CryptoUtils.generateX25519KeyPair();
        KeyPair bobEph = CryptoUtils.generateX25519KeyPair();

        byte[] aliceRawEph = CryptoUtils.getRawX25519PublicKey(aliceEph.getPublic());
        byte[] bobRawEph = CryptoUtils.getRawX25519PublicKey(bobEph.getPublic());

        byte[] aliceSig = CryptoUtils.signEd25519(aliceId.getPrivate(), aliceRawEph);
        byte[] bobSig = CryptoUtils.signEd25519(bobId.getPrivate(), bobRawEph);

        assertTrue(CryptoUtils.verifyEd25519(aliceId.getPublic(), aliceRawEph, aliceSig));
        assertTrue(CryptoUtils.verifyEd25519(bobId.getPublic(), bobRawEph, bobSig));

        byte[] s1 = CryptoUtils.x25519SharedSecret(aliceEph.getPrivate(), bobEph.getPublic());
        byte[] s2 = CryptoUtils.x25519SharedSecret(bobEph.getPrivate(), aliceEph.getPublic());

        assertArrayEquals(s1, s2);

        byte[] k1 = CryptoUtils.hkdf(s1, "p2p-file-transfer", 32);
        byte[] k2 = CryptoUtils.hkdf(s2, "p2p-file-transfer", 32);

        assertArrayEquals(k1, k2);
    }
}