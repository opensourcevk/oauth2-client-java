package com.mastercard.developer.oauth2.core.access_token;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

@SuppressWarnings("OptionalGetWithoutIsPresent") // Simpler assertions
class InMemoryAccessTokenStoreTest extends BaseTest {

    @Test
    void put_ShouldStoreDPoPBoundAccessToken() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, sampleAccessToken);

        // WHEN
        store.put(accessToken);

        // THEN
        assertEquals(accessToken, store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).get());
        assertEquals(accessToken, store.get(AccessTokenFilter.byScopes(sampleScopes)).get());
    }

    @Test
    void put_ShouldReplaceDPoPBoundAccessToken_WhenSameJktAndScopes() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var firstToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, "first_token");
        var secondToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, "second_token");
        store.put(firstToken);

        // WHEN
        store.put(secondToken);

        // THEN
        assertEquals(secondToken, store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).get());
        assertEquals(secondToken, store.get(AccessTokenFilter.byScopes(sampleScopes)).get());
    }

    @Test
    void put_ShouldStoreBearerAccessToken() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleAccessToken);

        // WHEN
        store.put(accessToken);

        // THEN
        assertEquals(accessToken, store.get(AccessTokenFilter.byScopes(sampleScopes)).get());
    }

    @Test
    void put_ShouldReplaceBearerAccessToken_WhenSameScopes() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var firstToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, "first_token");
        var secondToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, "second_token");
        store.put(firstToken);

        // WHEN
        store.put(secondToken);

        // THEN
        assertEquals(secondToken, store.get(AccessTokenFilter.byScopes(sampleScopes)).get());
    }

    @Test
    void put_ShouldNotReplaceDPoPBoundAccessToken_WhenBearerAccessTokenWithSameScopes() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var firstToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, "first_token");
        var secondToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, "second_token");
        store.put(firstToken);

        // WHEN
        store.put(secondToken);

        // THEN
        assertEquals(firstToken, store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).get());
        assertEquals(secondToken, store.get(AccessTokenFilter.byScopes(sampleScopes)).get());
    }

    @Test
    void put_ShouldReplaceBothAccessTokens_WhenDPoPBoundAccessTokenWithSameScopes() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var firstToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, "first_token");
        var secondToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, "second_token");
        store.put(firstToken);

        // WHEN
        store.put(secondToken);

        // THEN
        assertEquals(secondToken, store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).get());
        assertEquals(secondToken, store.get(AccessTokenFilter.byScopes(sampleScopes)).get());
    }

    @Test
    void put_ShouldRemoveExpiredTokens_WhenAddingNewToken() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var differentJkt = "different_jkt";
        var differentScopes = Set.of("service:scope3");
        var expiredToken = new AccessToken(sampleClientId, sampleScopes, samplePastInstant, sampleJkt, "expired_token");
        var validToken = new AccessToken(sampleClientId, differentScopes, sampleFutureInstant, differentJkt, sampleAccessToken);
        store.put(expiredToken);

        // WHEN
        store.put(validToken);

        // THEN
        assertFalse(store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).isPresent());
        assertFalse(store.get(AccessTokenFilter.byScopes(sampleScopes)).isPresent());
    }

    @Test
    void get_ShouldReturnEmpty_WhenTokenDoesNotExist() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();

        // WHEN / THEN
        assertFalse(store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).isPresent());
        assertFalse(store.get(AccessTokenFilter.byScopes(sampleScopes)).isPresent());
    }

    @Test
    void get_ShouldReturnEmpty_WhenTokenExpired() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        store.put(new AccessToken(sampleClientId, sampleScopes, samplePastInstant, sampleJkt, sampleAccessToken));

        // WHEN / THEN
        assertFalse(store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).isPresent());
        assertFalse(store.get(AccessTokenFilter.byScopes(sampleScopes)).isPresent());
    }

    @Test
    void get_ShouldReturnToken_WhenScopesInDifferentOrder() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var scopes = new LinkedHashSet<>(Set.of("service:scope2", "service:scope1"));
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, sampleAccessToken);
        store.put(accessToken);

        // WHEN / THEN
        assertEquals(accessToken, store.get(AccessTokenFilter.byScopes(scopes)).get());
        assertEquals(accessToken, store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, scopes)).get());
    }

    @Test
    void get_ShouldReturnEmpty_WhenScopesMismatch() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        store.put(new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, sampleAccessToken));
        var scopeSets = List.of(
            Set.of("service:scope3"),
            Set.<String>of(),
            new HashSet<>(sampleScopes) {
                {
                    add("service:scope3");
                }
            }
        );

        // WHEN / THEN
        for (Set<String> scopes : scopeSets) {
            assertFalse(store.get(AccessTokenFilter.byScopes(scopes)).isPresent());
            assertFalse(store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, scopes)).isPresent());
        }
    }

    @Test
    void get_ShouldReturnToken_WhenEmptyScopes() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var scopes = Set.<String>of();
        var accessToken = new AccessToken(sampleClientId, scopes, sampleFutureInstant, sampleJkt, sampleAccessToken);
        store.put(accessToken);

        // WHEN / THEN
        assertTrue(store.get(AccessTokenFilter.byScopes(scopes)).isPresent());
        assertTrue(store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, scopes)).isPresent());
    }

    @Test
    void get_ShouldReturnEmpty_WhenTokenExpiresInLessThan60Seconds() {
        // GIVEN
        var store = new InMemoryAccessTokenStore();
        var in59Seconds = Instant.now().plusSeconds(59);
        var accessToken = new AccessToken(sampleClientId, sampleScopes, in59Seconds, sampleJkt, sampleAccessToken);
        store.put(accessToken);

        // WHEN / THEN
        assertFalse(store.get(AccessTokenFilter.byJktAndScopes(sampleJkt, sampleScopes)).isPresent());
        assertFalse(store.get(AccessTokenFilter.byScopes(sampleScopes)).isPresent());
    }
}
