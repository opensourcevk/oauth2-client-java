package com.mastercard.developer.oauth2.http;

import static com.mastercard.developer.oauth2.test.helpers.SystemPropertyUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UserAgentTest {

    @Test
    void get_ShouldReturnFormattedUserAgent() {
        // Save original properties
        String originalJavaVersion = get("java.version");
        String originalOsName = get("os.name");
        String originalOsVersion = get("os.version");

        try {
            // Set deterministic properties
            set("java.version", "11.0.1");
            set("os.name", "TestOS");
            set("os.version", "9");

            assertEquals("Mastercard-OAuth2-Client/1.2.3-test (Java/11.0.1; TestOS 9)", UserAgent.get());
        } finally {
            // Restore original properties using shared helper
            restore("java.version", originalJavaVersion);
            restore("os.name", originalOsName);
            restore("os.version", originalOsVersion);
        }
    }
}
