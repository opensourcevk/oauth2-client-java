package com.mastercard.developer.oauth2.test.helpers;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jwt.SignedJWT;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Checks test JWS signatures using Nimbus.
 */
public class JwsUtils {

    /**
     * Checks that the signature of the given JWT is valid using the provided public key.
     */
    public static void checkSignatureValid(SignedJWT jwt, PublicKey publicKey) throws Exception {
        JWSVerifier verifier;
        if (publicKey instanceof RSAPublicKey) {
            verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        } else if (publicKey instanceof ECPublicKey) {
            verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        } else {
            throw new IllegalStateException("Unsupported key type");
        }
        if (!jwt.verify(verifier)) {
            throw new IllegalStateException("Invalid JWT signature");
        }
    }

    /**
     * Checks that the signature of the given JWT is valid using the public key from its JWK header.
     */
    public static void checkSignatureValid(SignedJWT jwt) throws Exception {
        PublicKey publicKey = ((AsymmetricJWK) jwt.getHeader().getJWK()).toPublicKey();
        checkSignatureValid(jwt, publicKey);
    }
}
