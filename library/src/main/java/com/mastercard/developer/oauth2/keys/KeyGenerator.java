package com.mastercard.developer.oauth2.keys;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

/**
 * Utility class for generating RSA or EC key pairs.
 */
public final class KeyGenerator {

    private KeyGenerator() {
        // Utility class
    }

    /**
     * Generates an RSA key pair with the specified key size.
     */
    public static KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates an EC key pair with the specified curve.
     */
    public static KeyPair generateEcKeyPair(String curveName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        var keyPairGenerator = KeyPairGenerator.getInstance("EC");
        var ecSpec = new ECGenParameterSpec(curveName);
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }
}
