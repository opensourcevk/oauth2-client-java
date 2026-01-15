package com.mastercard.developer.oauth2.config;

import static com.mastercard.developer.oauth2.test.helpers.EolUtils.normalizeEOL;
import static com.mastercard.developer.oauth2.test.helpers.SystemPropertyUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import com.mastercard.developer.oauth2.config.OAuth2Config.OAuth2ConfigBuilder;
import com.mastercard.developer.oauth2.config.exception.OAuth2ClientConfigException;
import com.mastercard.developer.oauth2.core.dpop.DPoPKey;
import com.mastercard.developer.oauth2.core.dpop.DPoPKeyProvider;
import com.mastercard.developer.oauth2.core.dpop.StaticDPoPKeyProvider;
import com.mastercard.developer.oauth2.http.UserAgent;
import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import com.mastercard.developer.oauth2.test.fixtures.StaticKeys;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class OAuth2ConfigTest extends BaseTest {

    @Test
    void build_ShouldCreateConfig_WhenAllFieldsProvided() {
        // WHEN
        OAuth2Config config = sampleConfigBuilder.build();

        // THEN
        assertEquals(sampleClientId, config.getClientId());
        assertEquals(sampleTokenEndpoint, config.getTokenEndpoint());
        assertEquals(sampleIssuer, config.getIssuer());
        assertEquals(sampleClockSkewTolerance, config.getClockSkewTolerance());
        assertEquals(sampleUserAgent, config.getUserAgent());
        assertSame(sampleAccessTokenStore, config.getAccessTokenStore());
        assertEquals(sampleClientKey, config.getClientKey());
        assertEquals(sampleClientKid, config.getKid());
        assertEquals(sampleDpopKeyProvider, config.getDPoPKeyProvider());
    }

    @Test
    void clientId_ShouldTrimClientId_WhenClientIdContainsWhitespace() {
        // GIVEN
        sampleConfigBuilder.clientId("  my-client  ");

        // WHEN
        OAuth2Config config = sampleConfigBuilder.build();

        // THEN
        assertEquals("my-client", config.getClientId());
    }

    @Test
    void kid_ShouldTrimKid_WhenKidContainsWhitespace() {
        // GIVEN
        sampleConfigBuilder.kid("  my-kid  ");

        // WHEN
        OAuth2Config config = sampleConfigBuilder.build();

        // THEN
        assertEquals("my-kid", config.getKid());
    }

    @Test
    void clockSkewTolerance_ShouldThrowConfigException_WhenValueIsNull() {
        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, () -> sampleConfigBuilder.clockSkewTolerance(null));
        assertEquals("Clock skew tolerance must be positive", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void clockSkewTolerance_ShouldThrowConfigException_WhenValueIsNegative() {
        // WHEN / THEN
        Duration duration = Duration.ofSeconds(-1);
        var ex = assertThrows(OAuth2ClientConfigException.class, () -> sampleConfigBuilder.clockSkewTolerance(duration));
        assertEquals("Clock skew tolerance must be positive", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenClientIdMissing() {
        // GIVEN
        OAuth2ConfigBuilder builder = OAuth2Config.builder()
            .issuer(sampleIssuer)
            .tokenEndpoint(sampleTokenEndpoint)
            .clientKey(sampleClientKey)
            .kid(sampleClientKid)
            .dpopKeyProvider(sampleDpopKeyProvider);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, builder::build);
        assertEquals("Client ID is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenTokenEndpointMissing() {
        // GIVEN
        sampleConfigBuilder.tokenEndpoint(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Token endpoint is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenIssuerMissing() {
        // GIVEN
        sampleConfigBuilder.issuer(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Issuer is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenScopeResolverMissing() {
        // GIVEN
        sampleConfigBuilder.scopeResolver(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Scope resolver is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenAccessTokenStoreMissing() {
        // GIVEN
        sampleConfigBuilder.accessTokenStore(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Token store is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenUserAgentMissing() {
        // GIVEN
        sampleConfigBuilder.userAgent(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("User agent is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldUseDefaultUserAgent_WhenUserAgentNotSpecified() {
        // GIVEN
        OAuth2ConfigBuilder builder = OAuth2Config.builder()
            .clientId(sampleClientId)
            .tokenEndpoint(sampleTokenEndpoint)
            .issuer(sampleIssuer)
            .scopeResolver(sampleScopeResolver)
            .clientKey(sampleClientKey)
            .kid(sampleClientKid)
            .dpopKeyProvider(sampleDpopKeyProvider);

        // WHEN
        OAuth2Config config = builder.build();

        // THEN
        assertEquals(UserAgent.get(), config.getUserAgent());
    }

    @Test
    void build_ShouldThrowConfigException_WhenClientKeyMissing() {
        // GIVEN
        sampleConfigBuilder.clientKey(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Client private key is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenKidMissing() {
        // GIVEN
        sampleConfigBuilder.kid("   ");

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Key ID (kid) is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenDPoPKeyProviderMissing() {
        // GIVEN
        sampleConfigBuilder.dpopKeyProvider(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("DPoP key provider is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenSecurityProfileMissing() {
        // GIVEN
        sampleConfigBuilder.securityProfile(null);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Security profile is required", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenDPoPKeyNull() {
        // GIVEN
        var dpopKeyProvider = Mockito.mock(DPoPKeyProvider.class);
        when(dpopKeyProvider.getCurrentKey()).thenReturn(null);
        sampleConfigBuilder.dpopKeyProvider(dpopKeyProvider);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("DPoP key provider must return a valid DPoP key", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenDPoPKeyPairNull() {
        // GIVEN
        var dpopKeyProvider = Mockito.mock(DPoPKeyProvider.class);
        var dpopKey = Mockito.mock(DPoPKey.class);
        when(dpopKey.getKeyPair()).thenReturn(null);
        when(dpopKey.getKeyId()).thenReturn(sampleDpopKid);
        when(dpopKeyProvider.getCurrentKey()).thenReturn(dpopKey);
        sampleConfigBuilder.dpopKeyProvider(dpopKeyProvider);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("DPoP key provider must return a valid DPoP key", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenDPoPKeyIdNull() {
        // GIVEN
        var dpopKeyProvider = Mockito.mock(DPoPKeyProvider.class);
        var dpopKey = Mockito.mock(DPoPKey.class);
        when(dpopKey.getKeyPair()).thenReturn(sampleDpopKey);
        when(dpopKey.getKeyId()).thenReturn(null);
        when(dpopKeyProvider.getCurrentKey()).thenReturn(dpopKey);
        sampleConfigBuilder.dpopKeyProvider(dpopKeyProvider);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("DPoP key provider must return a valid DPoP key ID", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenNonRsaAndNonEcDPoPKey() {
        // GIVEN
        var dpopKeyProvider = Mockito.mock(DPoPKeyProvider.class);
        var dpopKey = Mockito.mock(DPoPKey.class);
        when(dpopKey.getKeyPair()).thenReturn(StaticKeys.DSA_KEY_PAIR); // Not "RSA" and not "EC"
        when(dpopKey.getKeyId()).thenReturn(sampleDpopKid);
        when(dpopKeyProvider.getCurrentKey()).thenReturn(dpopKey);
        sampleConfigBuilder.dpopKeyProvider(dpopKeyProvider);

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Key algorithm must be RSA or EC, but was: DSA", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenRsaDPoPKeyWithKeyLessThan2048Bits() {
        // GIVEN
        sampleConfigBuilder.dpopKeyProvider(new StaticDPoPKeyProvider(StaticKeys.WEAK_RSA_KEY_PAIR));

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("RSA keys must have a minimum length of 2048 bits, but key length was: 512", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenEcDPoPKeyWithLessThan224Bits() {
        // GIVEN
        sampleConfigBuilder.dpopKeyProvider(new StaticDPoPKeyProvider(StaticKeys.WEAK_EC_KEY_PAIR));

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Elliptic curve keys must have a minimum length of 224 bits, but key length was: 192", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenNonRsaAndNonEcClientKey() {
        // GIVEN
        sampleConfigBuilder.clientKey(StaticKeys.DSA_KEY_PAIR.getPrivate()); // Not "RSA" and not "EC"

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Key algorithm must be RSA or EC, but was: DSA", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenRsaClientKeyWithKeyLessThan2048Bits() {
        // GIVEN
        sampleConfigBuilder.clientKey(StaticKeys.WEAK_RSA_KEY_PAIR.getPrivate());

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("RSA keys must have a minimum length of 2048 bits, but key length was: 512", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void build_ShouldThrowConfigException_WhenEcClientKeyWithLessThan224Bits() {
        // GIVEN
        sampleConfigBuilder.clientKey(StaticKeys.WEAK_EC_KEY_PAIR.getPrivate());

        // WHEN / THEN
        var ex = assertThrows(OAuth2ClientConfigException.class, sampleConfigBuilder::build);
        assertEquals("Elliptic curve keys must have a minimum length of 224 bits, but key length was: 192", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void toString_ShouldIncludeAllFields() {
        // Save original properties
        String originalJavaVersion = get("java.version");
        String originalOsName = get("os.name");
        String originalOsVersion = get("os.version");

        try {
            // GIVEN
            set("java.version", "17.0.14");
            set("os.name", "Windows 11");
            set("os.version", "10.0");
            OAuth2Config config = sampleConfigBuilder.build();

            // WHEN
            String actual = config.toString();

            // THEN
            var expected = """
                OAuth2Config {
                  clientId='ZvT0sklPsqzTNgKJIiex5_wppXz0Tj2wl33LUZtXmCQH8dry',
                  tokenEndpoint='https://sandbox.api.mastercard.com/oauth/token',
                  issuer='https://sandbox.api.mastercard.com',
                  clockSkewTolerance='PT5S',
                  userAgent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
                  accessTokenStore='InMemoryAccessTokenStore',
                  scopeResolver='StaticScopeResolver',
                  kid='302449525fad5309874b16298f3cbaaf0000000000000000',
                  clientKey='PrivateKey[class=RSAPrivateKeyImpl, algorithm=RSA, format=PKCS#8]',
                  dpopKeyProvider='StaticDPoPKeyProvider',
                  securityProfile='FAPI2SP_PRIVATE_KEY_DPOP'
                }""";
            assertEquals(normalizeEOL(expected), normalizeEOL(actual));
        } finally {
            // Restore original properties using shared helper
            restore("java.version", originalJavaVersion);
            restore("os.name", originalOsName);
            restore("os.version", originalOsVersion);
        }
    }
}
