package com.mastercard.developer.oauth2.internal.jose;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import com.mastercard.developer.oauth2.test.fixtures.StaticKeys;
import com.mastercard.developer.oauth2.test.helpers.JwsUtils;
import com.nimbusds.jwt.SignedJWT;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import org.junit.jupiter.api.Test;

class JwsTest {

    @Test
    void sign_ShouldProduceValidPS256Signature_WhenUsingRSAKey() throws Exception {
        // GIVEN
        KeyPair rsaKeyPair = StaticKeys.RSA_KEY_PAIR;
        var jwt = new Jwt();
        jwt.addHeaderParam("typ", "JWT");
        jwt.addClaim("sub", "test-rsa");

        // WHEN
        Jws.sign(jwt, rsaKeyPair.getPrivate(), JwsAlgorithm.PS256);
        String jwtString = jwt.getSerialized();

        // THEN
        SignedJWT signedJwt = SignedJWT.parse(jwtString);
        JwsUtils.checkSignatureValid(signedJwt, rsaKeyPair.getPublic());
    }

    @Test
    void sign_ShouldProduceValidES256Signature_WhenUsingECKey() throws Exception {
        // GIVEN
        KeyPair ecKeyPair = StaticKeys.EC_KEY_PAIR;
        var jwt = new Jwt();
        jwt.addHeaderParam("typ", "JWT");
        jwt.addClaim("sub", "test-ec");

        // WHEN
        Jws.sign(jwt, ecKeyPair.getPrivate(), JwsAlgorithm.ES256);
        String jwtString = jwt.getSerialized();

        // THEN
        SignedJWT signedJwt = SignedJWT.parse(jwtString);
        JwsUtils.checkSignatureValid(signedJwt, ecKeyPair.getPublic());
    }

    @Test
    void sign_ShouldThrowOAuth2ClientException_WhenSigningWithRsaKeyButUsingEs256() {
        // GIVEN
        KeyPair rsaKeyPair = StaticKeys.RSA_KEY_PAIR;
        var jwt = new Jwt();
        jwt.addHeaderParam("typ", "JWT");
        jwt.addClaim("sub", "wrong-key-type");

        // WHEN / THEN
        PrivateKey privateKey = rsaKeyPair.getPrivate();
        var ex = assertThrows(OAuth2ClientException.class, () -> Jws.sign(jwt, privateKey, JwsAlgorithm.ES256));
        assertEquals("Failed to sign JWT", ex.getMessage());
        assertInstanceOf(InvalidKeyException.class, ex.getCause());
    }

    @Test
    void sign_ShouldThrowOAuth2ClientException_WhenSigningWithEcKeyButUsingPs256() {
        // GIVEN
        KeyPair ecKeyPair = StaticKeys.EC_KEY_PAIR;
        var jwt = new Jwt();
        jwt.addHeaderParam("typ", "JWT");
        jwt.addClaim("sub", "wrong-key-type");

        // WHEN / THEN
        PrivateKey privateKey = ecKeyPair.getPrivate();
        var ex = assertThrows(OAuth2ClientException.class, () -> Jws.sign(jwt, privateKey, JwsAlgorithm.PS256));
        assertEquals("Failed to sign JWT", ex.getMessage());
        assertInstanceOf(InvalidKeyException.class, ex.getCause());
    }
}
