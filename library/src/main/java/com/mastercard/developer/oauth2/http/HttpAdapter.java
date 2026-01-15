package com.mastercard.developer.oauth2.http;

import java.net.URL;
import java.util.Optional;

/**
 * Abstraction for HTTP operations across different HTTP client implementations.
 */
@SuppressWarnings("squid:S00119") // For readability, we keep generic type names as 'Request' and 'Response'
public interface HttpAdapter<Request, Response> {
    /**
     * Extracts the HTTP method from a request.
     */
    String getMethod(Request request);

    /**
     * Extracts the URL from a request.
     */
    URL getUrl(Request request) throws Exception;

    /**
     * Sends a token request to an authorization server.
     */
    Response sendAccessTokenRequest(Request resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) throws Exception;

    /**
     * Sends a resource request to a resource server.
     */
    Response sendResourceRequest(Request request, HttpHeaders headers) throws Exception;

    /**
     * Gets the status code from a response.
     */
    int getStatusCode(Response response) throws Exception;

    /**
     * Gets a header value from a response.
     */
    Optional<String> getHeader(Response response, String name) throws Exception;

    /**
     * Reads a response body as a string.
     */
    Optional<String> readBody(Response response) throws Exception;

    /**
     * Closes a response and releases resources.
     */
    void close(Response response) throws Exception;
}
