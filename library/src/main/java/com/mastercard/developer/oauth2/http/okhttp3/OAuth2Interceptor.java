package com.mastercard.developer.oauth2.http.okhttp3;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler;
import java.io.IOException;
import okhttp3.*;

/**
 * An OAuth2 interceptor for OkHttp.
 */
@SuppressWarnings("NullableProblems") // OkHttp API nullability varies across versions
public final class OAuth2Interceptor implements Interceptor {

    private final OAuth2Handler handler;
    private final OkHttpAdapter adapter;

    /**
     * Creates a new OAuth2 interceptor for OkHttp.
     * @param config       A OAuth2 configuration.
     * @param baseBuilder  A OkHttpClient builder to use as a starting point.
     */
    public OAuth2Interceptor(OAuth2Config config, OkHttpClient.Builder baseBuilder) {
        this.handler = new OAuth2Handler(config);
        this.adapter = new OkHttpAdapter(baseBuilder.build());
    }

    /**
     * Creates a new OAuth2 interceptor for OkHttp.
     * @param config      A OAuth2 configuration.
     */
    public OAuth2Interceptor(OAuth2Config config) {
        this(config, new OkHttpClient.Builder());
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        try {
            return handler.execute(chain, adapter);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to execute request", e);
        }
    }
}
