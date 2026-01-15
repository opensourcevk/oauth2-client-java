package com.mastercard.developer.oauth2.internal.jose;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

/**
 * Provides JWT signing functionality using JWS algorithms.
 * See also: <a href="https://openid.net/specs/fapi-security-profile-2_0-final.html#name-cryptography-and-secrets">5.4. Cryptography and secrets</a>
 */
public final class Jws {

    private Jws() {
        // Static class
    }

    /**
     * Signs a JWT using the specified private key and algorithm.
     */
    public static void sign(Jwt jwt, PrivateKey privateKey, JwsAlgorithm alg) {
        try {
            jwt.addHeaderParam("alg", alg.alg());
            String signingInput = jwt.getSigningInput();
            byte[] signatureBytes = signBytes(signingInput.getBytes(StandardCharsets.US_ASCII), privateKey, alg);
            jwt.setSignature(Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes));
        } catch (Exception e) {
            throw new OAuth2ClientException("Failed to sign JWT", e);
        }
    }

    private static byte[] signBytes(byte[] data, PrivateKey key, JwsAlgorithm alg)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature sig;
        switch (alg) {
            case PS256:
                sig = Signature.getInstance("RSASSA-PSS");
                sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                break;
            case ES256:
                sig = Signature.getInstance("SHA256withECDSAinP1363Format"); // Can emit ECDSA signatures in the P1363 (r||s) format directly
                break;
            default:
                throw new IllegalStateException("Unsupported alg: " + alg);
        }
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }
}
