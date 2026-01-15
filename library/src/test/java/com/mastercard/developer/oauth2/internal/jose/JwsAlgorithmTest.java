package com.mastercard.developer.oauth2.internal.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.mastercard.developer.oauth2.test.fixtures.StaticKeys;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;

class JwsAlgorithmTest {

    @Test
    void fromKey_ShouldReturnPs256_WhenRsaPublicKeyProvided() {
        // WHEN
        var algorithm = JwsAlgorithm.fromKey(StaticKeys.RSA_KEY_PAIR.getPublic());

        // THEN
        assertEquals(JwsAlgorithm.PS256, algorithm);
    }

    @Test
    void fromKey_ShouldReturnEs256_WhenEcPublicKeyProvided() {
        // WHEN
        var algorithm = JwsAlgorithm.fromKey(StaticKeys.EC_KEY_PAIR.getPublic());

        // THEN
        assertEquals(JwsAlgorithm.ES256, algorithm);
    }

    @Test
    void fromKey_ShouldReturnPs256_WhenRsaPrivateKeyProvided() {
        // WHEN
        var algorithm = JwsAlgorithm.fromKey(StaticKeys.RSA_KEY_PAIR.getPrivate());

        // THEN
        assertEquals(JwsAlgorithm.PS256, algorithm);
    }

    @Test
    void fromKey_ShouldReturnEs256_WhenEcPrivateKeyProvided() {
        // WHEN
        var algorithm = JwsAlgorithm.fromKey(StaticKeys.EC_KEY_PAIR.getPrivate());

        // THEN
        assertEquals(JwsAlgorithm.ES256, algorithm);
    }

    @Test
    void fromKey_ShouldThrowIllegalStateException_WhenUnsupportedKeyTypeProvided() {
        // WHEN / THEN
        PublicKey dsaKey = StaticKeys.DSA_KEY_PAIR.getPublic();
        assertThrows(IllegalStateException.class, () -> JwsAlgorithm.fromKey(dsaKey));
    }
}
