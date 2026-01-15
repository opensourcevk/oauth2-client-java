package com.mastercard.developer.oauth2.internal.jose;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import com.mastercard.developer.oauth2.test.fixtures.StaticKeys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JwkTest {

    @Test
    void fromKey_ShouldCreateRsaJwk_WhenRsaKeyProvided() {
        // WHEN
        var jwk = Jwk.fromKey(StaticKeys.RSA_KEY_PAIR.getPublic());

        // THEN
        assertEquals("RSA", jwk.get("kty"));
        assertEquals("AQAB", jwk.get("e"));
        assertEquals(
            "wxnY2XfkJDaA_qIYUHMbT_5RXnE1xK2YdDiwRwuo1JaNa_aZhqqw4u1dg9ztvyCpsbL_VL_FaExSSrK6OSmQJYpisUROuxC1ep6Vn7IcuzJmmhUX_vaElWFCEAST5LuFdgnBR8wmChVTh4BHDXmmL0NzJVGXnzwcQN1COP26usmi8-HB5Vr0COYqD8TdVcYywfsuhbiQY0uFyl8HQuIdiNx4TZBut3nv4Ii33n1HwlESTxgkmTnnOIwEVicug7sep4lh-5mXaGMhObIXzz-SZl2hMwRHpWFr8HH_youIUfbSEgSWmJsvw5PA4XY4awWdUnC-9U7tKGsE36VWfqfDJw",
            jwk.get("n")
        );
        assertEquals(3, jwk.size()); // Only kty, e, n for RSA
    }

    @Test
    void fromKey_ShouldCreateEcJwk_WhenEcKeyProvided() {
        // WHEN
        var jwk = Jwk.fromKey(StaticKeys.EC_KEY_PAIR.getPublic());

        // THEN
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertEquals("cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc", jwk.get("x"));
        assertEquals("89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8", jwk.get("y"));
        assertEquals(4, jwk.size()); // kty, crv, x, y for EC
    }

    @Test
    void fromKey_ShouldThrowIllegalStateException_WhenUnsupportedKeyTypeProvided() {
        // WHEN
        PublicKey dsaKey = StaticKeys.DSA_KEY_PAIR.getPublic();
        var ex = assertThrows(IllegalArgumentException.class, () -> Jwk.fromKey(dsaKey));

        // THEN
        assertEquals("Unsupported public key type: " + dsaKey.getClass().getName(), ex.getMessage());
    }

    @Test
    void computeThumbprint_ShouldReturnDeterministicValue_WhenRsaKeyProvided() {
        // GIVEN
        var jwk = Jwk.fromKey(StaticKeys.RSA_KEY_PAIR.getPublic());

        // WHEN
        String jkt = jwk.computeThumbprint();

        // THEN
        assertEquals("-cSeNq9eyhJsLmX6Nxg_qZ7H0heh0tqnFwkEIlHfRkc", jkt);
    }

    @Test
    void computeThumbprint_ShouldReturnDeterministicValue_WhenEcKeyProvided() {
        // GIVEN
        var jwk = Jwk.fromKey(StaticKeys.EC_KEY_PAIR.getPublic());

        // WHEN
        String jkt = jwk.computeThumbprint();

        // THEN
        assertEquals("7xwyqRziWGktjyBbPC5j4WxsqowZo62GXLTQJqcmjxI", jkt);
    }

    @Test
    void fromJson_ShouldParseRsaJwk_WhenValidRsaJsonProvided() throws IOException {
        // GIVEN
        var keyPath = "./src/test/resources/keys/jwk/test_rsa.json";
        var rsaJson = new String(Files.readAllBytes(Path.of(keyPath)));

        // WHEN
        var jwk = Jwk.fromJson(rsaJson);

        // THEN
        assertEquals("RSA", jwk.get("kty"));
        assertEquals("AQAB", jwk.get("e"));
        assertEquals(
            "wxnY2XfkJDaA_qIYUHMbT_5RXnE1xK2YdDiwRwuo1JaNa_aZhqqw4u1dg9ztvyCpsbL_VL_FaExSSrK6OSmQJYpisUROuxC1ep6Vn7IcuzJmmhUX_vaElWFCEAST5LuFdgnBR8wmChVTh4BHDXmmL0NzJVGXnzwcQN1COP26usmi8-HB5Vr0COYqD8TdVcYywfsuhbiQY0uFyl8HQuIdiNx4TZBut3nv4Ii33n1HwlESTxgkmTnnOIwEVicug7sep4lh-5mXaGMhObIXzz-SZl2hMwRHpWFr8HH_youIUfbSEgSWmJsvw5PA4XY4awWdUnC-9U7tKGsE36VWfqfDJw",
            jwk.get("n")
        );
        assertEquals(
            "DfdFsfDby0ko3BFtEs_f6U6tMx4rg9QMERXAbfWEX7i_OuFA2tumeeK_9PaAVlQs5uQx_uETbS85ciYadTO9ISgnfxpYAHARGEv4g0v-s9pxxHSKGTLltBkYNN6pr4_03R7ppQ1qE61fI1ioEsDd3ThDf9e4C4AEDb3zmvIexyFpOQvdqXvUpfNhb1s1hsLRU-_cltFnjuLBxFOixx2AQBWQyBm9ZbYK94BP5znKHkedYMsS6Y4NrIbxMZIEIiJMYw2k77ub5n3iwMBFNa3sE5BEMJTr2or5wMMnQdJ9fKYLdQN8bFjbC408nHNoVQViX302ApZ8NhsJAfAzW6NJ0Q",
            jwk.get("d")
        );
    }

    @Test
    void fromJson_ShouldParseEcJwk_WhenValidEcJsonProvided() throws IOException {
        // GIVEN
        var keyPath = "./src/test/resources/keys/jwk/test_ec.json";
        var ecJson = new String(Files.readAllBytes(Path.of(keyPath)));

        // WHEN
        var jwk = Jwk.fromJson(ecJson);

        // THEN
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertEquals("cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc", jwk.get("x"));
        assertEquals("89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8", jwk.get("y"));
        assertEquals("QSmrwP5VQoH7PzWJ3ZTKhG7S_Wr1zDP8ko6-z7SLTa8", jwk.get("d"));
    }

    // GIVEN
    private static Stream<Arguments> invalidJwkJsonProvider() {
        return Stream.of(
            Arguments.of(
                """
                {"crv":"P-256","x":"test","y":"test","d":"test"}
                """,
                "Missing required JWK parameter: kty"
            ),
            Arguments.of(
                """
                {"kty":"DSA","n":"test","e":"test","d":"test"}
                """,
                "Unsupported key type: DSA"
            ),
            Arguments.of(
                """
                {"kty":"RSA","e":"AQAB"}
                """,
                "Missing required RSA JWK parameters (n, e, d)"
            ),
            Arguments.of(
                """
                {"kty":"EC","crv":"P-256"}
                """,
                "Missing required EC JWK parameters (crv, x, y, d)"
            ),
            Arguments.of("invalid json", "Unable to parse JWK JSON")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidJwkJsonProvider")
    void fromJson_ShouldThrowOAuth2ClientException_WhenInvalidOrMissingParametersProvided(String invalidJson, String expectedMessage) {
        // WHEN
        var ex = assertThrows(OAuth2ClientException.class, () -> Jwk.fromJson(invalidJson));

        // THEN
        assertEquals(expectedMessage, ex.getMessage());
    }

    @Test
    void toKeyPair_ShouldReturnRsaKeyPair_WhenRsaJwkProvided() throws IOException {
        // GIVEN
        var keyPath = "./src/test/resources/keys/jwk/test_rsa.json";
        var rsaJson = new String(Files.readAllBytes(Path.of(keyPath)));
        var jwk = Jwk.fromJson(rsaJson);

        // WHEN
        var keyPair = jwk.toKeyPair();

        // THEN
        assertInstanceOf(RSAPublicKey.class, keyPair.getPublic());
        assertInstanceOf(RSAPrivateKey.class, keyPair.getPrivate());
    }

    @Test
    void toKeyPair_ShouldReturnEcKeyPair_WhenEcJwkProvided() throws IOException {
        // GIVEN
        var keyPath = "./src/test/resources/keys/jwk/test_ec.json";
        var ecJson = new String(Files.readAllBytes(Path.of(keyPath)));
        var jwk = Jwk.fromJson(ecJson);

        // WHEN
        var keyPair = jwk.toKeyPair();

        // THEN
        assertInstanceOf(ECPublicKey.class, keyPair.getPublic());
        assertInstanceOf(ECPrivateKey.class, keyPair.getPrivate());
    }
}
