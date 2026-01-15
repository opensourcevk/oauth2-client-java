package com.mastercard.developer.oauth2.config.exception;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import java.net.MalformedURLException;
import org.junit.jupiter.api.Test;

class OAuth2ClientConfigExceptionTest {

    @Test
    void constructor_ShouldSetMessage_WhenMessageProvided() {
        // GIVEN
        var message = "configuration is invalid";

        // WHEN
        var exception = new OAuth2ClientConfigException(message);

        // THEN
        assertEquals(message, exception.getMessage());
        assertInstanceOf(OAuth2ClientException.class, exception, "Should be a subtype of OAuth2ClientException");
    }

    @Test
    void constructor_ShouldSetMessageAndCause_WhenMessageAndCauseProvided() {
        // GIVEN
        var message = "malformed endpoint";
        Throwable cause = new MalformedURLException("no protocol");

        // WHEN
        var exception = new OAuth2ClientConfigException(message, cause);

        // THEN
        assertEquals(message, exception.getMessage());
        assertSame(cause, exception.getCause());
        assertInstanceOf(OAuth2ClientException.class, exception, "Should be a subtype of OAuth2ClientException");
    }
}
