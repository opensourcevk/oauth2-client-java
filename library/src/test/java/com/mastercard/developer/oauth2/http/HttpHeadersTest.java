package com.mastercard.developer.oauth2.http;

import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HttpHeadersTest {

    private HttpHeaders headers;

    @BeforeEach
    void setUp() {
        headers = new HttpHeaders();
    }

    @Test
    void add_ShouldAddHeader_WhenValueIsProvided() {
        // GIVEN
        var headerValue = "application/json";

        // WHEN
        headers.add(CONTENT_TYPE, headerValue);

        // THEN
        assertEquals(1, headers.size());
        assertTrue(headers.contains(CONTENT_TYPE.value()));
    }

    @Test
    void add_ShouldReplaceExistingHeader_WhenHeaderAlreadyExists() {
        // GIVEN
        headers.add(CONTENT_TYPE, "text/plain");
        var newValue = "application/json";

        // WHEN
        headers.add(CONTENT_TYPE, newValue);

        // THEN
        assertEquals(1, headers.size());
        var value = headers.get(CONTENT_TYPE.value());
        assertTrue(value.isPresent());
        assertEquals(newValue, value.get());
    }

    @Test
    void add_ShouldNotAddHeader_WhenValueIsNull() {
        // WHEN
        headers.add(CONTENT_TYPE, null);

        // THEN
        assertEquals(0, headers.size());
    }

    @Test
    void add_ShouldNotAddHeader_WhenValueIsEmpty() {
        // WHEN
        headers.add(CONTENT_TYPE, "");

        // THEN
        assertEquals(0, headers.size());
    }

    @Test
    void add_ShouldReturnThis_WhenCalledForChaining() {
        // WHEN
        var result = headers.add(CONTENT_TYPE, "application/json");

        // THEN
        assertSame(headers, result);
    }

    @Test
    void add_ShouldAllowChaining_WhenAddingMultipleHeaders() {
        // WHEN
        headers.add(CONTENT_TYPE, "application/json").add(AUTHORIZATION, "Bearer token");

        // THEN
        assertEquals(2, headers.size());
    }

    @Test
    void get_ShouldReturnValue_WhenHeaderExists() {
        // GIVEN
        var expectedValue = "application/json";
        headers.add(CONTENT_TYPE, expectedValue);

        // WHEN
        var result = headers.get(CONTENT_TYPE.value());

        // THEN
        assertTrue(result.isPresent());
        assertEquals(expectedValue, result.get());
    }

    @Test
    void get_ShouldReturnEmpty_WhenHeaderDoesNotExist() {
        // WHEN
        var result = headers.get("Non-Existent-Header");

        // THEN
        assertTrue(result.isEmpty());
    }

    @Test
    void get_ShouldBeCaseInsensitive_WhenLookingUpHeader() {
        // GIVEN
        headers.add(CONTENT_TYPE, "application/json");

        // WHEN
        var result = headers.get("content-type");

        // THEN
        assertTrue(result.isPresent());
        assertEquals("application/json", result.get());
    }

    @Test
    void contains_ShouldReturnTrue_WhenHeaderExists() {
        // GIVEN
        headers.add(CONTENT_TYPE, "application/json");

        // WHEN
        var result = headers.contains(CONTENT_TYPE.value());

        // THEN
        assertTrue(result);
    }

    @Test
    void contains_ShouldReturnFalse_WhenHeaderDoesNotExist() {
        // WHEN
        var result = headers.contains("Non-Existent-Header");

        // THEN
        assertFalse(result);
    }

    @Test
    void contains_ShouldBeCaseInsensitive_WhenCheckingHeader() {
        // GIVEN
        headers.add(CONTENT_TYPE, "application/json");

        // WHEN
        var result = headers.contains("CONTENT-TYPE");

        // THEN
        assertTrue(result);
    }

    @Test
    void httpHeader_ShouldStoreNameAndValue_WhenCreated() {
        // GIVEN
        var name = "Custom-Header";
        var value = "custom-value";

        // WHEN
        var header = new HttpHeaders.HttpHeader(name, value);

        // THEN
        assertEquals(name, header.name());
        assertEquals(value, header.value());
    }
}
