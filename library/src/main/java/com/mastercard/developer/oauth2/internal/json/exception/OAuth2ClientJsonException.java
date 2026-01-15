package com.mastercard.developer.oauth2.internal.json.exception;

/**
 * Exception for JSON errors.
 */
public class OAuth2ClientJsonException extends Exception {

    /**
     * Creates a new JSON exception with the specified message.
     */
    public OAuth2ClientJsonException(String message) {
        super(message);
    }

    /**
     * Creates a new JSON exception with the specified message and cause.
     */
    public OAuth2ClientJsonException(String message, Throwable cause) {
        super(message, cause);
    }
}
