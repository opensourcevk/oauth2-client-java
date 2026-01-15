package com.mastercard.developer.oauth2.internal.jose;

import java.security.Key;

/**
 * Represents signing algorithms supported for JWT signing.
 * See also: <a href="https://openid.net/specs/fapi-security-profile-2_0-final.html#name-cryptography-and-secrets">5.4. Cryptography and secrets</a>
 */
public enum JwsAlgorithm {
    PS256("PS256"),
    ES256("ES256");

    private final String alg;

    JwsAlgorithm(String alg) {
        this.alg = alg;
    }

    /**
     * Returns the algorithm name as used in JWT headers.
     */
    public String alg() {
        return alg;
    }

    /**
     * Determines the appropriate signing algorithm based on the key type.
     */
    public static JwsAlgorithm fromKey(Key key) {
        return switch (key.getAlgorithm()) {
            case "RSA" -> PS256;
            case "EC" -> ES256;
            default -> throw new IllegalStateException("Unsupported key type: " + key.getAlgorithm());
        };
    }
}
