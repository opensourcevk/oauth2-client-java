package com.mastercard.developer.oauth2.core.dpop;

import static org.junit.jupiter.api.Assertions.*;

import com.mastercard.developer.oauth2.test.fixtures.BaseTest;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class StaticDPoPKeyProviderTest extends BaseTest {

    @Test
    void constructor_ShouldComputeKeyIdAndExposeKeyPair_WhenValidKeyPairProvided() {
        // GIVEN
        KeyPair keyPair = sampleDpopKey;

        // WHEN
        var provider = new StaticDPoPKeyProvider(keyPair);

        // THEN
        assertSame(keyPair, provider.getCurrentKey().getKeyPair());
        assertEquals("7xwyqRziWGktjyBbPC5j4WxsqowZo62GXLTQJqcmjxI", provider.getCurrentKey().getKeyId());
        assertSame(keyPair, provider.getKey("7xwyqRziWGktjyBbPC5j4WxsqowZo62GXLTQJqcmjxI").getKeyPair());
    }
}
