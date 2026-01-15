package com.mastercard.developer.oauth2.http;

import java.util.LinkedHashSet;
import java.util.Optional;

/**
 * Represents a set of HTTP headers.
 */
public final class HttpHeaders extends LinkedHashSet<HttpHeaders.HttpHeader> {

    /**
     * Adds/replaces a header.
     */
    public HttpHeaders add(StandardHttpHeader header, String value) {
        if (value != null && !value.isEmpty()) {
            var headerName = header.value();
            removeIf(h -> h.name().equalsIgnoreCase(headerName));
            add(new HttpHeader(headerName, value));
        }
        return this;
    }

    /**
     * Gets the value of the header with the given name.
     */
    public Optional<String> get(String headerName) {
        return stream()
            .filter(header -> header.name().equalsIgnoreCase(headerName))
            .findFirst()
            .map(HttpHeader::value);
    }

    /**
     * Checks if a header with the given name exists.
     */
    public boolean contains(String name) {
        return stream().anyMatch(header -> header.name().equalsIgnoreCase(name));
    }

    /**
     * Represents a single header entry.
     */
    public record HttpHeader(String name, String value) {}
}
