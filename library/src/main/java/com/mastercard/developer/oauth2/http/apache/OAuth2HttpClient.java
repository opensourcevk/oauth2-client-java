package com.mastercard.developer.oauth2.http.apache;

import static com.mastercard.developer.oauth2.http.apache.ApacheHttpAdapter.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler;
import java.io.IOException;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.io.CloseMode;

/**
 * An OAuth2-enabled Apache HttpClient.
 */
public class OAuth2HttpClient extends CloseableHttpClient {

    private final OAuth2Handler handler;
    private final CloseableHttpClient delegate;
    private final ApacheHttpAdapter adapter;

    /**
     * Creates a new OAuth2-enabled Apache HttpClient.
     * @param config   A OAuth2 configuration.
     * @param delegate The underlying HttpClient to delegate requests to.
     */
    public OAuth2HttpClient(OAuth2Config config, CloseableHttpClient delegate) {
        this.handler = new OAuth2Handler(config);
        this.delegate = delegate;
        this.adapter = new ApacheHttpAdapter(delegate);
    }

    /**
     * Creates a new OAuth2-enabled Apache HttpClient using a default HttpClient delegate.
     * @param config   A OAuth2 configuration.
     */
    public OAuth2HttpClient(OAuth2Config config) {
        this(config, HttpClients.createDefault());
    }

    @Override
    protected CloseableHttpResponse doExecute(HttpHost target, ClassicHttpRequest request, HttpContext context) throws IOException {
        try {
            return handler.execute(new ApacheRequestContext(target, request, context), adapter);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to execute request", e);
        }
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public void close(CloseMode closeMode) {
        delegate.close(closeMode);
    }
}
