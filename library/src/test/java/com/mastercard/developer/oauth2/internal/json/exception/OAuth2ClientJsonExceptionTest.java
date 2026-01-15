package com.mastercard.developer.oauth2.internal.json.exception;

import static org.junit.jupiter.api.Assertions.*;

import java.net.MalformedURLException;
import org.junit.jupiter.api.Test;

class OAuth2ClientJsonExceptionTest {

    @Test
    void constructor_ShouldSetMessage_WhenMessageProvided() {
        // GIVEN
        var message = "configuration is invalid";

        // WHEN
        var exception = new OAuth2ClientJsonException(message);

        // THEN
        assertEquals(message, exception.getMessage());
        assertInstanceOf(Exception.class, exception, "Should be a subtype of Exception");
    }

    @Test
    void constructor_ShouldSetMessageAndCause_WhenMessageAndCauseProvided() {
        // GIVEN
        var message = "malformed endpoint";
        Throwable cause = new MalformedURLException("no protocol");

        // WHEN
        var exception = new OAuth2ClientJsonException(message, cause);

        // THEN
        assertEquals(message, exception.getMessage());
        assertSame(cause, exception.getCause());
        assertInstanceOf(Exception.class, exception, "Should be a subtype of Exception");
    }
}
