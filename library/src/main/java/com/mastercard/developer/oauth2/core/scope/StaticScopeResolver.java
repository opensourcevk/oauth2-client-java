package com.mastercard.developer.oauth2.core.scope;

import java.net.URL;
import java.util.Collections;
import java.util.Set;

/**
 * A {@link ScopeResolver} that always returns a fixed list of scopes regardless of the URL.
 */
public record StaticScopeResolver(Set<String> scopes) implements ScopeResolver {
    /**
     * Creates a new {@link StaticScopeResolver} with the given scopes.
     * If the provided set is null, an empty set will be used instead.
     */
    public StaticScopeResolver(Set<String> scopes) {
        this.scopes = scopes == null ? Collections.emptySet() : Set.copyOf(scopes);
    }

    @Override
    public Set<String> resolve(String httpMethod, URL url) {
        // 'httpMethod' and 'url' aren't used here, this provider always returns the same scopes
        return scopes;
    }

    @Override
    public Set<String> allScopes() {
        return scopes;
    }
}
