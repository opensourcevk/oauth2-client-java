package com.mastercard.developer.oauth2.keys;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.Test;

class KeyGeneratorTest {

    @Test
    void generateRsaKeyPair_ShouldReturnValidKeyPair() throws Exception {
        // GIVEN
        int keySize = 2048;

        // WHEN
        KeyPair keyPair = KeyGenerator.generateRsaKeyPair(keySize);

        // THEN
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        assertEquals(2048, rsaPublicKey.getModulus().bitLength());
    }

    @Test
    void generateRsaKeyPair_ShouldThrowInvalidParameterException_WhenInvalidCurve() {
        // GIVEN
        int keySize = 0;

        // WHEN & THEN
        assertThrows(InvalidParameterException.class, () -> KeyGenerator.generateRsaKeyPair(keySize));
    }

    @Test
    void generateEcKeyPair_ShouldReturnValidKeyPair_WhenSecp256r1() throws Exception {
        // GIVEN
        String curveName = "secp256r1";

        // WHEN
        KeyPair keyPair = KeyGenerator.generateEcKeyPair(curveName);

        // THEN
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
        var ecPublic = (ECPublicKey) keyPair.getPublic();
        assertEquals(256, ecPublic.getParams().getOrder().bitLength());
    }

    @Test
    void generateEcKeyPair_ShouldThrowInvalidAlgorithmParameterException_WhenInvalidCurve() {
        // GIVEN
        String invalidCurve = "invalid-curve";

        // WHEN & THEN
        assertThrows(InvalidAlgorithmParameterException.class, () -> KeyGenerator.generateEcKeyPair(invalidCurve));
    }
}
