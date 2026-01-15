package com.mastercard.developer.oauth2.core;

import static org.junit.jupiter.api.Assertions.*;
import static org.skyscreamer.jsonassert.JSONAssert.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler.AccessTokenResponse;
import com.mastercard.developer.oauth2.core.dpop.StaticDPoPKeyProvider;
import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import com.mastercard.developer.oauth2.internal.json.exception.OAuth2ClientJsonException;
import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import com.mastercard.developer.oauth2.test.fixtures.StaticKeys;
import com.mastercard.developer.oauth2.test.helpers.JwsUtils;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link OAuth2Handler} utility/static methods.
 */
class OAuth2HandlerStaticTest extends BaseTest {

    @Test
    void createClientAssertion_ShouldCreateValidSignature_WhenRsaKey() throws Exception {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.clientKey(StaticKeys.RSA_KEY_PAIR.getPrivate()).build();
        String clientAssertion = OAuth2Handler.createClientAssertion(config);

        // THEN
        var jwt = SignedJWT.parse(clientAssertion);
        JWSHeader header = jwt.getHeader();
        assertEquals("PS256", header.getAlgorithm().getName());
        JwsUtils.checkSignatureValid(jwt, StaticKeys.RSA_KEY_PAIR.getPublic());
    }

    @Test
    void createClientAssertion_ShouldCreateValidSignature_WhenEcKey() throws Exception {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.clientKey(StaticKeys.EC_KEY_PAIR.getPrivate()).build();
        String clientAssertion = OAuth2Handler.createClientAssertion(config);

        // THEN
        var jwt = SignedJWT.parse(clientAssertion);
        JWSHeader header = jwt.getHeader();
        assertEquals("ES256", header.getAlgorithm().getName());
        JwsUtils.checkSignatureValid(jwt, StaticKeys.EC_KEY_PAIR.getPublic());
    }

    @Test
    void createClientAssertion_ShouldIncludeExpectedParameters() throws Exception {
        // WHEN
        String clientAssertion = OAuth2Handler.createClientAssertion(sampleConfigBuilder.build());

        // THEN
        var jwt = SignedJWT.parse(clientAssertion);
        JWSHeader header = jwt.getHeader();
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertEquals(sampleClientKid, header.getKeyID());
        assertEquals("PS256", header.getAlgorithm().getName());
        assertEquals("JWT", header.getType().getType());
        assertNotNull(jwtClaimsSet.getClaim("jti"));
        assertEquals(sampleClientId, jwtClaimsSet.getClaim("sub"));
        assertEquals(sampleClientId, jwtClaimsSet.getClaim("iss"));
        assertEquals(List.of(sampleIssuer.toString()), jwtClaimsSet.getClaim("aud"));
        var iat = (Date) jwtClaimsSet.getClaim("iat");
        var exp = (Date) jwtClaimsSet.getClaim("exp");
        var nbf = (Date) jwtClaimsSet.getClaim("nbf");
        assertDateCloseFrom(iat, Instant.now());
        assertDateCloseFrom(exp, Instant.now().plusSeconds(90).plusSeconds(sampleClockSkewTolerance.getSeconds()));
        assertDateCloseFrom(nbf, Instant.now().minusSeconds(sampleClockSkewTolerance.getSeconds()));
    }

    @Test
    void createTokenRequestDPoP_ShouldCreateValidSignature_WhenRsaKey() throws Exception {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.dpopKeyProvider(new StaticDPoPKeyProvider(StaticKeys.RSA_KEY_PAIR)).build();
        String dpopProof = OAuth2Handler.createTokenRequestDPoP(config, sampleDpopKid, sampleNonce);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWSHeader header = jwt.getHeader();
        assertEquals("PS256", header.getAlgorithm().getName());
        JwsUtils.checkSignatureValid(jwt);
    }

    @Test
    void createTokenRequestDPoP_ShouldCreateValidSignature_WhenEcKey() throws Exception {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.dpopKeyProvider(new StaticDPoPKeyProvider(StaticKeys.EC_KEY_PAIR)).build();
        String dpopProof = OAuth2Handler.createTokenRequestDPoP(config, sampleDpopKid, sampleNonce);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWSHeader header = jwt.getHeader();
        assertEquals("ES256", header.getAlgorithm().getName());
        JwsUtils.checkSignatureValid(jwt);
    }

    @Test
    void createTokenRequestDPoP_ShouldIncludeExpectedParameters() throws Exception {
        // WHEN
        var sampleTokenEndpointUrlWithQueryAndFragment = URI.create(sampleTokenEndpoint + "?param=value#section").toURL();
        String dpopProof = OAuth2Handler.createTokenRequestDPoP(sampleConfigBuilder.tokenEndpoint(sampleTokenEndpointUrlWithQueryAndFragment).build(), sampleDpopKid, sampleNonce);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWSHeader header = jwt.getHeader();
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertEquals(sampleDpopKid, header.getKeyID());
        assertEquals("ES256", header.getAlgorithm().getName());
        assertEquals("dpop+jwt", header.getType().getType());
        assertEquals(
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc\",\"y\":\"89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8\"}",
            header.getJWK().toString(),
            true
        );
        assertNotNull(jwtClaimsSet.getClaim("jti"));
        var iat = (Date) jwtClaimsSet.getClaim("iat");
        var exp = (Date) jwtClaimsSet.getClaim("exp");
        assertDateCloseFrom(iat, Instant.now());
        assertDateCloseFrom(exp, Instant.now().plusSeconds(90).plusSeconds(sampleClockSkewTolerance.getSeconds()));
        assertEquals(sampleNonce, jwtClaimsSet.getClaim("nonce"));
        assertEquals("POST", jwtClaimsSet.getClaim("htm"));
        assertEquals(sampleTokenEndpoint.toString(), jwtClaimsSet.getClaim("htu"));
    }

    @Test
    void createTokenRequestDPoP_ShouldNotIncludeNonce_WhenNonceNotProvided() throws Exception {
        // WHEN
        String dpopProof = OAuth2Handler.createTokenRequestDPoP(sampleConfigBuilder.build(), sampleDpopKid, null);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertNull(jwtClaimsSet.getClaim("nonce"));
    }

    @Test
    void createResourceRequestDPoP_ShouldCreateValidSignature_WhenRsaKey() throws Exception {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.dpopKeyProvider(new StaticDPoPKeyProvider(StaticKeys.RSA_KEY_PAIR)).build();
        String dpopProof = OAuth2Handler.createResourceRequestDPoP(config, sampleDpopKid, sampleResourceMethod, sampleResourceUrl, sampleAccessToken, sampleNonce);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWSHeader header = jwt.getHeader();
        assertEquals("PS256", header.getAlgorithm().getName());
        JwsUtils.checkSignatureValid(jwt);
    }

    @Test
    void createResourceRequestDPoP_ShouldCreateValidSignature_WhenEcKey() throws Exception {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.dpopKeyProvider(new StaticDPoPKeyProvider(StaticKeys.EC_KEY_PAIR)).build();
        String dpopProof = OAuth2Handler.createResourceRequestDPoP(config, sampleDpopKid, sampleResourceMethod, sampleResourceUrl, sampleAccessToken, sampleNonce);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWSHeader header = jwt.getHeader();
        assertEquals("ES256", header.getAlgorithm().getName());
        JwsUtils.checkSignatureValid(jwt);
    }

    @Test
    void createResourceRequestDPoP_ShouldIncludeExpectedParameters() throws Exception {
        // WHEN
        var sampleResourceUrlWithQueryAndFragment = sampleResourceUrl + "?param=value#section";
        String dpopProof = OAuth2Handler.createResourceRequestDPoP(
            sampleConfigBuilder.build(),
            sampleDpopKid,
            sampleResourceMethod,
            sampleResourceUrlWithQueryAndFragment,
            sampleAccessToken,
            sampleNonce
        );

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWSHeader header = jwt.getHeader();
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertEquals(sampleDpopKid, header.getKeyID());
        assertEquals("ES256", header.getAlgorithm().getName());
        assertEquals("dpop+jwt", header.getType().getType());
        assertEquals(
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"cojbH-aPEUBxt2_uSx5P9UTUkl5X_CFbnncJ35-onlc\",\"y\":\"89bpkg2grnJC0rzo_I2c_BTLB0sXHBvbmu5jjSwyOv8\"}",
            header.getJWK().toString(),
            true
        );
        assertNotNull(jwtClaimsSet.getClaim("jti"));
        var iat = (Date) jwtClaimsSet.getClaim("iat");
        var exp = (Date) jwtClaimsSet.getClaim("exp");
        assertDateCloseFrom(iat, Instant.now());
        assertDateCloseFrom(exp, Instant.now().plusSeconds(90).plusSeconds(sampleClockSkewTolerance.getSeconds()));
        assertEquals(sampleNonce, jwtClaimsSet.getClaim("nonce"));
        assertEquals(sampleResourceMethod, jwtClaimsSet.getClaim("htm"));
        assertEquals(sampleResourceUrl, jwtClaimsSet.getClaim("htu"));
        assertEquals(sampleAth, jwtClaimsSet.getClaim("ath"));
    }

    @Test
    void createResourceRequestDPoP_ShouldNotIncludeNonce_WhenNonceNotProvided() throws Exception {
        // WHEN
        String dpopProof = OAuth2Handler.createResourceRequestDPoP(sampleConfigBuilder.build(), sampleDpopKid, sampleResourceMethod, sampleResourceUrl, "test", null);

        // THEN
        var jwt = SignedJWT.parse(dpopProof);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertNull(jwtClaimsSet.getClaim("nonce"));
    }

    @Test
    void parseAccessTokenJson_ShouldReturnAccessTokenResponse_WhenValidJsonProvided() {
        // GIVEN
        var jsonResponse = sampleAccessTokenResponse;

        // WHEN
        var beforeCall = Instant.now();
        AccessTokenResponse accessTokenResponse = OAuth2Handler.parseAccessTokenJson(jsonResponse);
        var afterCall = Instant.now();

        // THEN
        assertEquals(sampleAccessToken, accessTokenResponse.tokenValue());
        assertEquals(Set.of("service:scope1", "service:scope2"), accessTokenResponse.scopes());
        assertTrue(accessTokenResponse.expiry().isAfter(beforeCall.plusSeconds(3598)));
        assertTrue(accessTokenResponse.expiry().isBefore(afterCall.plusSeconds(3602)));
    }

    @Test
    void parseAccessTokenJson_ShouldThrowException_WhenNullValue() {
        var ex = assertThrows(OAuth2ClientException.class, () -> OAuth2Handler.parseAccessTokenJson(null));
        assertEquals("Empty access token response", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void parseAccessTokenJson_ShouldThrowException_WhenEmptyValue() {
        var ex = assertThrows(OAuth2ClientException.class, () -> OAuth2Handler.parseAccessTokenJson(""));
        assertEquals("Empty access token response", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void parseAccessTokenJson_ShouldThrowException_WhenAccessTokenValueMissing() {
        // GIVEN
        var jsonResponse = """
            {
                "token_type": "DPoP",
                "scope": "service:scope1 service:scope2",
                "expires_in": 3600
            }
            """;

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientException.class, () -> OAuth2Handler.parseAccessTokenJson(jsonResponse));
        assertEquals("Missing value in access token response: access_token", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void parseAccessTokenJson_ShouldThrowException_WhenExpiresInValueMissing() {
        // GIVEN
        var jsonResponse = String.format(
            """
            {
                "access_token": "%s",
                "token_type": "DPoP",
                "scope": "service:scope1 service:scope2"
            }
            """,
            sampleAccessToken
        );

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientException.class, () -> OAuth2Handler.parseAccessTokenJson(jsonResponse));
        assertEquals("Missing value in access token response: expires_in", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void parseAccessTokenJson_ShouldReturnEmptyScopes_WhenScopeValueMissing() {
        // GIVEN
        var jsonResponse = String.format(
            """
            {
                "access_token": "%s",
                "token_type": "DPoP",
                "expires_in": 3600
            }
            """,
            sampleAccessToken
        );

        // WHEN / THEN
        AccessTokenResponse accessTokenResponse = OAuth2Handler.parseAccessTokenJson(jsonResponse);

        // THEN
        assertEquals(Set.of(), accessTokenResponse.scopes());
    }

    @Test
    void parseAccessTokenJson_ShouldThrowException_WhenInvalidJson() {
        // GIVEN
        var invalidJson = "not a valid json";

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientException.class, () -> OAuth2Handler.parseAccessTokenJson(invalidJson));
        assertEquals("Failed to parse JSON access token response", ex.getMessage());
        var cause = ex.getCause();
        assertInstanceOf(OAuth2ClientJsonException.class, cause);
        assertEquals("Failed to read JSON", cause.getMessage());
    }

    @Test
    void createAccessTokenRequestBody_ShouldReturnUrlEncodedForm() {
        // WHEN
        String body = OAuth2Handler.createAccessTokenRequestBody(sampleClientId, sampleScopeValue, "jwt.assertion.here");

        // THEN
        assertEquals(
            "client_id=ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry&grant_type=client_credentials&scope=service%3Ascope1%2C+service%3Ascope2&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=jwt.assertion.here",
            body
        );
    }

    @Test
    void createAccessTokenRequestBody_ShouldHandleEmptyScope() {
        // WHEN
        String body = OAuth2Handler.createAccessTokenRequestBody(sampleClientId, "", "jwt.assertion.here");

        // THEN
        assertEquals(
            "client_id=ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry&grant_type=client_credentials&scope=&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=jwt.assertion.here",
            body
        );
    }

    private static void assertDateCloseFrom(Date date, Instant instant) {
        var dateInstant = date.toInstant();
        var diffSeconds = Math.abs(dateInstant.getEpochSecond() - instant.getEpochSecond());
        assertTrue(diffSeconds <= 2, "Date " + dateInstant + " not within 2 seconds of " + instant);
    }
}
