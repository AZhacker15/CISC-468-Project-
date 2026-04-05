package crypto;

import java.security.*;

public class KeyManager {
    private KeyPair keyPair;

    public void loadOrCreateKeys() throws Exception {
        keyPair = CryptoUtils.generateEd25519KeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public byte[] getRawPublicKey() {
        return CryptoUtils.getRawEd25519PublicKey(keyPair.getPublic());
    }
}