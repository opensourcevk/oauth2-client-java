package com.mastercard.developer.oauth2.exception;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class OAuth2ClientExceptionTest {

    @Test
    void constructor_ShouldSetMessage_WhenMessageProvided() {
        // GIVEN
        var message = "an unexpected error occurred";

        // WHEN
        var exception = new OAuth2ClientException(message);

        // THEN
        assertEquals(message, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void constructor_ShouldSetMessageAndCause_WhenMessageAndCauseProvided() {
        // GIVEN
        var message = "failed due to invalid input";
        var rootCause = new IllegalArgumentException("invalid");

        // WHEN
        var exception = new OAuth2ClientException(message, rootCause);

        // THEN
        assertEquals(message, exception.getMessage());
        assertSame(rootCause, exception.getCause());
    }
}
