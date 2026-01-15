package com.mastercard.developer.oauth2.config.exception;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;

/**
 * Exception for configuration errors.
 */
public class OAuth2ClientConfigException extends OAuth2ClientException {

    /**
     * Creates a new configuration exception with the specified message.
     */
    public OAuth2ClientConfigException(String message) {
        super(message);
    }

    /**
     * Creates a new configuration exception with the specified message and cause.
     */
    public OAuth2ClientConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
