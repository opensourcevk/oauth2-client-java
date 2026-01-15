package com.mastercard.developer.oauth2.internal.jose;

import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtTest {

    private Jwt jwt;

    @BeforeEach
    void setUp() {
        jwt = new Jwt();
    }

    @Test
    void addHeaderParam_ShouldAddParam_WhenValueNotNull() throws Exception {
        // GIVEN
        var key = "alg";
        var value = "PS256";

        // WHEN
        jwt.addHeaderParam(key, value);

        // THEN
        String signingInput = jwt.getSigningInput();
        String decodedHeader = decodeHeader(signingInput);
        assertEquals("{\"alg\":\"PS256\"}", decodedHeader, true);
    }

    @Test
    void addHeaderParam_ShouldRemoveParam_WhenValueNull() throws Exception {
        // GIVEN
        jwt.addHeaderParam("alg", "PS256");

        // WHEN
        jwt.addHeaderParam("alg", null);

        // THEN
        String signingInput = jwt.getSigningInput();
        String decodedHeader = decodeHeader(signingInput);
        assertEquals("{}", decodedHeader, true);
    }

    @Test
    void addClaim_ShouldAddClaim_WhenValueNotNull() throws Exception {
        // GIVEN
        var key = "sub";
        var value = "user123";

        // WHEN
        jwt.addClaim(key, value);

        // THEN
        String signingInput = jwt.getSigningInput();
        String decodedPayload = decodePayload(signingInput);
        assertEquals("{\"sub\":\"user123\"}", decodedPayload, true);
    }

    @Test
    void addClaim_ShouldRemoveClaim_WhenValueNull() throws Exception {
        // GIVEN
        jwt.addClaim("sub", "user123");

        // WHEN
        jwt.addClaim("sub", null);

        // THEN
        String signingInput = jwt.getSigningInput();
        String decodedPayload = decodePayload(signingInput);
        assertEquals("{}", decodedPayload, true);
    }

    @Test
    void getSigningInput_ShouldReturnCorrectString_WhenHeaderAndPayloadSet() throws Exception {
        // GIVEN
        jwt.addHeaderParam("alg", "PS256");
        jwt.addClaim("sub", "user123");

        // WHEN
        String signingInput = jwt.getSigningInput();

        // THEN
        assertEquals("eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0", signingInput);
    }

    @Test
    void getJwsCompactSerialization_ShouldReturnSerialized_WhenSignatureSet() throws Exception {
        // GIVEN
        jwt.addHeaderParam("alg", "PS256");
        jwt.addClaim("sub", "user123");
        var signature = "signature123";

        // WHEN
        jwt.setSignature(signature);
        String jwsString = jwt.getSerialized();

        // THEN
        assertEquals("eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature123", jwsString);
    }

    @Test
    void getSerialized_ShouldThrowIllegalStateException_WhenSignatureNull() {
        // GIVEN
        jwt.addHeaderParam("alg", "PS256");
        jwt.addClaim("sub", "user123");

        // WHEN / THEN
        assertThrows(IllegalStateException.class, () -> jwt.getSerialized());
    }

    private static String decodeHeader(String signingInput) {
        String header = signingInput.split("\\.")[0];
        return new String(Base64.getUrlDecoder().decode(header), StandardCharsets.UTF_8);
    }

    private static String decodePayload(String signingInput) {
        String payload = signingInput.split("\\.")[1];
        return new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
    }
}
