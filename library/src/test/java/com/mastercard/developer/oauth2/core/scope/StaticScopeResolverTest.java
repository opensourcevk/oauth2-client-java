package com.mastercard.developer.oauth2.core.scope;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class StaticScopeResolverTest extends BaseTest {

    @Test
    void resolve_ShouldReturnFixedScopes() throws Exception {
        // GIVEN
        var method = "GET";
        var url = URI.create("https://example.com/resource").toURL();
        var resolver = new StaticScopeResolver(sampleScopes);

        // WHEN
        Set<String> scopes = resolver.resolve(method, url);

        // THEN
        assertEquals(sampleScopes, scopes);
    }

    @Test
    void allScopes_ShouldReturnFixedScopes() {
        // GIVEN
        var resolver = new StaticScopeResolver(sampleScopes);

        // WHEN
        Set<String> scopes = resolver.allScopes();

        // THEN
        assertEquals(sampleScopes, scopes);
    }

    @Test
    void constructor_ShouldReturnEmptySet_WhenNullIsPassed() {
        // GIVEN
        var nullResolver = new StaticScopeResolver(null);

        // WHEN / THEN
        assertTrue(nullResolver.allScopes().isEmpty());
    }

    @Test
    void constructor_ShouldReturnUnmodifiableSet_WhenSetIsPassed() {
        // GIVEN
        Set<String> scopes = new HashSet<>();
        scopes.add("service:scope3");
        var resolver = new StaticScopeResolver(scopes);

        // WHEN
        Set<String> returned = resolver.allScopes();

        // THEN
        assertThrows(UnsupportedOperationException.class, () -> returned.add("service:scope3"));
    }

    @Test
    void resolve_ShouldReturnEmptySet_WhenConstructedWithNull() throws Exception {
        // GIVEN
        var nullResolver = new StaticScopeResolver(null);
        var method = "GET";
        var url = URI.create("https://example.com/resource").toURL();

        // WHEN
        Set<String> scopes = nullResolver.resolve(method, url);

        // THEN
        assertTrue(scopes.isEmpty());
    }
}
