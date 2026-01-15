package com.mastercard.developer.oauth2.test.fixtures;

import com.mastercard.developer.oauth2.keys.KeyGenerator;
import com.mastercard.developer.oauth2.keys.KeyLoader;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class StaticKeys {

    public static final KeyPair RSA_KEY_PAIR;
    public static final KeyPair EC_KEY_PAIR;
    public static final KeyPair DSA_KEY_PAIR;
    public static final KeyPair WEAK_RSA_KEY_PAIR;
    public static final KeyPair WEAK_EC_KEY_PAIR;

    static {
        try {
            // Load a fixed RSA key pair
            RSA_KEY_PAIR = KeyLoader.loadKeyPair(Paths.get("./src/test/resources/keys/jwk/test_rsa.json"));

            // Load a fixed EC key pair
            EC_KEY_PAIR = KeyLoader.loadKeyPair(Paths.get("./src/test/resources/keys/jwk/test_ec.json"));

            // Generate a DSA key pair
            KeyPairGenerator dsaGen = KeyPairGenerator.getInstance("DSA");
            dsaGen.initialize(2048);
            DSA_KEY_PAIR = dsaGen.generateKeyPair();

            // Generate a weak RSA key pair
            WEAK_RSA_KEY_PAIR = KeyGenerator.generateRsaKeyPair(512);

            // Generate a weak EC key pair
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            var keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp192r1"));
            WEAK_EC_KEY_PAIR = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load or generate test keys", e);
        }
    }
}
