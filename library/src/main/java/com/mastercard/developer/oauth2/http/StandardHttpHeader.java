package com.mastercard.developer.oauth2.http;

/**
 * HTTP headers used by this project.
 */
public enum StandardHttpHeader {
    DPOP_NONCE("DPoP-Nonce"),
    USER_AGENT("User-Agent"),
    CONTENT_TYPE("Content-Type"),
    ACCEPT("Accept"),
    AUTHORIZATION("Authorization"),
    WWW_AUTHENTICATE("WWW-Authenticate"),
    DPOP("DPoP");

    private final String value;

    StandardHttpHeader(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
