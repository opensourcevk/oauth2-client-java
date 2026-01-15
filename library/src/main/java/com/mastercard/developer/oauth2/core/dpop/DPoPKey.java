package com.mastercard.developer.oauth2.core.dpop;

import java.security.KeyPair;

/**
 * Represents a DPoP key containing a key pair and its identifier.
 * DPoP keys are used to create DPoP proofs.
 */
public interface DPoPKey {
    /**
     * Gets the key pair used for signing DPoP proofs.
     */
    KeyPair getKeyPair();

    /**
     * Gets the key identifier ("kid" value that will be added to the DPoP proof header).
     */
    String getKeyId();
}
