package com.mastercard.developer.oauth2.core.dpop;

import com.mastercard.developer.oauth2.internal.jose.Jwk;
import java.security.KeyPair;

/**
 * Provides a static DPoP key pair that remains constant throughout the application lifecycle.
 * The key identifier is the public key thumbprint.
 * This provider is suitable for scenarios where key rotation is not required.
 */
public final class StaticDPoPKeyProvider implements DPoPKeyProvider {

    private final DPoPKey key;

    /**
     * Creates a new static DPoP key provider with the specified key pair.
     * The key identifier is automatically computed from the public key.
     */
    public StaticDPoPKeyProvider(KeyPair keyPair) {
        String kid = Jwk.fromKey(keyPair.getPublic()).computeThumbprint(); // In this implementation, 'kid' is the public key thumbprint
        key = new DPoPKey() {
            @Override
            public KeyPair getKeyPair() {
                return keyPair;
            }

            @Override
            public String getKeyId() {
                return kid;
            }
        };
    }

    @Override
    public DPoPKey getCurrentKey() {
        return key;
    }

    @Override
    public DPoPKey getKey(String kid) {
        // 'kid' isn't used here, this provider always returns the same key pair
        return key;
    }
}
