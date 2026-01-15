package com.mastercard.developer.oauth2.core.scope;

import java.net.URL;
import java.util.Set;

/**
 * Resolves OAuth2 scopes for API requests.
 * Implementations determine which scopes to include in token requests based on the HTTP method and target URL.
 */
public interface ScopeResolver {
    /**
     * Returns a set of scopes to request for an HTTP request to the given URL with the given method.
     */
    Set<String> resolve(String httpMethod, URL url);

    /**
     * Returns all possible scopes that can be requested.
     */
    Set<String> allScopes();
}
