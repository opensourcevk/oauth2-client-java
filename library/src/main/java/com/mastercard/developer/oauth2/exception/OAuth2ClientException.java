package com.mastercard.developer.oauth2.exception;

/**
 * General exception for OAuth2 client errors.
 */
public class OAuth2ClientException extends RuntimeException {

    /**
     * Creates a new {@link OAuth2ClientException} with the specified message.
     */
    public OAuth2ClientException(String message) {
        super(message);
    }

    /**
     * Creates a new {@link OAuth2ClientException} with the specified message and cause.
     */
    public OAuth2ClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
