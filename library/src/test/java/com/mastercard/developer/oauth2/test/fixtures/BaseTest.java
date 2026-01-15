package com.mastercard.developer.oauth2.test.fixtures;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.config.SecurityProfile;
import com.mastercard.developer.oauth2.core.access_token.AccessTokenStore;
import com.mastercard.developer.oauth2.core.access_token.InMemoryAccessTokenStore;
import com.mastercard.developer.oauth2.core.dpop.DPoPKeyProvider;
import com.mastercard.developer.oauth2.core.dpop.StaticDPoPKeyProvider;
import com.mastercard.developer.oauth2.core.scope.ScopeResolver;
import com.mastercard.developer.oauth2.core.scope.StaticScopeResolver;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public abstract class BaseTest {

    protected static DPoPKeyProvider sampleDpopKeyProvider;
    protected static String sampleJkt;
    protected static String sampleClientId;
    protected static PrivateKey sampleClientKey;
    protected static URL sampleTokenEndpoint;
    protected static URL sampleIssuer;
    protected static String sampleClientKid;
    protected static String sampleDpopKid;
    protected static KeyPair sampleDpopKey;
    protected static String sampleNonce;
    protected static String sampleResourceUrl;
    protected static String sampleResourceMethod;
    protected static String sampleAccessToken;
    protected static String sampleAccessTokenResponse;
    protected static String sampleAth;
    protected static String sampleScopeValue;
    protected static Set<String> sampleScopes;
    protected static Duration sampleClockSkewTolerance;
    protected static Instant sampleFutureInstant;
    protected static Instant samplePastInstant;
    protected static String sampleUserAgent;
    protected static ScopeResolver sampleScopeResolver;
    protected static AccessTokenStore sampleAccessTokenStore;

    protected OAuth2Config.OAuth2ConfigBuilder sampleConfigBuilder;

    @BeforeAll
    static void beforeAll() throws Exception {
        // GIVEN
        sampleDpopKey = StaticKeys.EC_KEY_PAIR;
        sampleClientKey = StaticKeys.RSA_KEY_PAIR.getPrivate();
        sampleDpopKeyProvider = new StaticDPoPKeyProvider(sampleDpopKey);
        sampleJkt = "7xwyqRziWGktjyBbPC5j4WxsqowZo62GXLTQJqcmjxI";
        sampleClientId = "ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry";
        sampleTokenEndpoint = URI.create("https://sandbox.api.mastercard.com/oauth/token").toURL();
        sampleIssuer = URI.create("https://sandbox.api.mastercard.com").toURL();
        sampleClientKid = "302449525fad5309874b16298f3cbaaf0000000000000000";
        sampleDpopKid = sampleDpopKeyProvider.getCurrentKey().getKeyId();
        sampleNonce = "5e8972513327f0b3670b21f308cf5e8e";
        sampleResourceUrl = "http://localhost:63972/api/resources/1";
        sampleResourceMethod = "GET";
        sampleAccessToken =
            "eyJ4NXQjUzI1NiI6Ii1sbjlQb1hyWFZQakxQTVVheC1zU29iWWhYQzNZakRfOFlvdWx2SHNjVjAiLCJraWQiOiJjN2QxZWE5Mi1kODAyLTRjZTYtYmI4NS1lZWNjZjlhOTgyZDMiLCJjdHkiOiJKV1MiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3NhbmRib3guYXBpLm1hc3RlcmNhcmQuY29tIiwic3ViIjoiWnZUMHNrbFBzcXpUTmdLSklpZXg1X3dwcFh6MFRqMndsMzNMVVp0WG1DUUg4ZHJ5IiwibmJmIjoxNzYwMDk5OTU2LCJzY29wZSI6InNlcnZpY2U6c2NvcGUxIHNlcnZpY2U6c2NvcGUyIiwiaXNzIjoiaHR0cHM6Ly9zYW5kYm94LmFwaS5tYXN0ZXJjYXJkLmNvbSIsImNuZiI6eyJqa3QiOiJ0UXpOVnZWZzF4OTluOGkta0dmRmZCenRMY2FxRlMyX25iOWJRa2wtRnFrIn0sImV4cCI6MTc2MDEwMDg2NiwiaWF0IjoxNzYwMDk5OTY2LCJqdGkiOiJjM2VhNzIwM2FhNDNjNDA3OTIxN2RhMjJlYjQ4NjZjNiJ9.vfuhb0QQkgTR7dj9J8Fc6RwhKCDhmtG2KlOsSFk-LolZXPXNQEKSvZsUVhGAoLTE69XYj5oPIq4PZf2WaMxLow";
        sampleAccessTokenResponse = String.format(
            """
            {
                "access_token": "%s",
                "token_type": "DPoP",
                "scope": "service:scope1 service:scope2",
                "expires_in": 3600
            }""",
            sampleAccessToken
        );
        sampleAth = "Syre2WyO2hFtZbC8v4_LF41uuF4ysyAxqIA-J6UnxLc";
        sampleScopeValue = "service:scope1, service:scope2";
        sampleScopes = new LinkedHashSet<>(List.of("service:scope1", "service:scope2"));
        sampleClockSkewTolerance = Duration.ofSeconds(5);
        sampleFutureInstant = Instant.now().plusSeconds(3600);
        samplePastInstant = Instant.now().minusSeconds(1);
        sampleUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
        sampleScopeResolver = new StaticScopeResolver(sampleScopes);
        sampleAccessTokenStore = new InMemoryAccessTokenStore();
    }

    @BeforeEach
    void setUp() {
        // GIVEN
        sampleConfigBuilder = OAuth2Config.builder()
            .securityProfile(SecurityProfile.FAPI2SP_PRIVATE_KEY_DPOP)
            .userAgent(sampleUserAgent)
            .clientId(sampleClientId)
            .clientKey(sampleClientKey)
            .tokenEndpoint(sampleTokenEndpoint)
            .issuer(sampleIssuer)
            .scopeResolver(sampleScopeResolver)
            .accessTokenStore(sampleAccessTokenStore)
            .kid(sampleClientKid)
            .clockSkewTolerance(sampleClockSkewTolerance)
            .dpopKeyProvider(sampleDpopKeyProvider);
    }
}
