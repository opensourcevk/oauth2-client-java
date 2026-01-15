package com.mastercard.developer.oauth2.core.access_token;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AccessTokenTest extends BaseTest {

    @Test
    void scopes_ShouldReturnUnmodifiableSet() {
        // GIVEN
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, sampleAccessToken);

        // WHEN / THEN
        Set<String> scopes = accessToken.scopes();
        assertThrows(UnsupportedOperationException.class, () -> scopes.add("service:scope3"));
    }

    @Test
    void scopes_ShouldReturnOriginalScopes_WhenOriginalSetModified() {
        // GIVEN
        var scopes = new HashSet<String>();
        var accessToken = new AccessToken(sampleClientId, scopes, sampleFutureInstant, sampleJkt, sampleAccessToken);
        scopes.add("service:scope3");

        // WHEN / THEN
        assertFalse(accessToken.scopes().contains("service:scope3"));
    }

    @Test
    void constructor_ShouldCreateAccessToken_WhenJktIsProvided() {
        // WHEN
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleJkt, sampleAccessToken);

        // THEN
        assertEquals(sampleClientId, accessToken.clientId());
        assertEquals(sampleAccessToken, accessToken.tokenValue());
        assertEquals(sampleScopes, accessToken.scopes());
        assertEquals(sampleFutureInstant, accessToken.expiresAt());
        assertEquals(sampleJkt, accessToken.jkt());
    }

    @Test
    void constructor_ShouldCreateAccessToken_WhenJktIsNotProvided() {
        // WHEN
        var accessToken = new AccessToken(sampleClientId, sampleScopes, sampleFutureInstant, sampleAccessToken);

        //  THEN
        assertEquals(sampleClientId, accessToken.clientId());
        assertEquals(sampleAccessToken, accessToken.tokenValue());
        assertEquals(sampleScopes, accessToken.scopes());
        assertEquals(sampleFutureInstant, accessToken.expiresAt());
        assertNull(accessToken.jkt());
    }

    @Test
    void constructor_ShouldUseEmptySet_WhenNullScopesProvided() {
        // WHEN
        var accessToken = new AccessToken(sampleClientId, null, sampleFutureInstant, sampleJkt, sampleAccessToken);

        // THEN
        assertEquals(Set.of(), accessToken.scopes());
    }
}
