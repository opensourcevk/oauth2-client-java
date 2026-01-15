package com.mastercard.developer.oauth2.http.spring.restclient;

import static com.mastercard.developer.oauth2.http.spring.restclient.RestClientHttpAdapter.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler;
import java.io.IOException;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * An OAuth2 interceptor for Spring RestClient.
 */
@SuppressWarnings("NullableProblems") // Spring API nullability varies across versions
public final class OAuth2ClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private final OAuth2Handler handler;
    private final RestClientHttpAdapter adapter;

    /**
     * Creates a new OAuth2 interceptor for Spring RestClient.
     * @param config      A OAuth2 configuration.
     */
    public OAuth2ClientHttpRequestInterceptor(OAuth2Config config) {
        this.handler = new OAuth2Handler(config);
        this.adapter = new RestClientHttpAdapter();
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        try {
            return handler.execute(new SpringRequestContext(request, new String(body), execution), adapter);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to execute request", e);
        }
    }
}
