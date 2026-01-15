package com.mastercard.developer.oauth2.http.feign;

import static com.mastercard.developer.oauth2.http.feign.FeignHttpAdapter.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler;
import feign.Client;
import feign.Request;
import feign.Response;
import java.io.IOException;

/**
 * An OAuth2-enabled Feign Client.
 */
public final class OAuth2Client implements Client {

    private final OAuth2Handler handler;
    private final FeignHttpAdapter adapter;

    /**
     * Creates a new OAuth2-enabled Feign Client.
     * @param config   A OAuth2 configuration.
     * @param delegate The underlying Client to delegate requests to.
     */
    public OAuth2Client(OAuth2Config config, Client delegate) {
        this.handler = new OAuth2Handler(config);
        this.adapter = new FeignHttpAdapter(delegate);
    }

    /**
     * Creates a new OAuth2-enabled Feign Client.
     * @param config   A OAuth2 configuration.
     */
    public OAuth2Client(OAuth2Config config) {
        this(config, new Client.Default(null, null));
    }

    @Override
    public Response execute(Request request, Request.Options options) throws IOException {
        try {
            return handler.execute(new FeignRequestContext(request, options), adapter);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to execute request", e);
        }
    }
}
