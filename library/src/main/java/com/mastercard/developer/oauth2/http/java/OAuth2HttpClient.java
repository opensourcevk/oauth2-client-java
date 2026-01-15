package com.mastercard.developer.oauth2.http.java;

import static com.mastercard.developer.oauth2.http.java.JavaHttpAdapter.*;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler;
import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * An OAuth2-enabled Java HttpClient.
 */
public final class OAuth2HttpClient extends HttpClient {

    private final OAuth2Handler handler;
    private final HttpClient delegate;
    private final JavaHttpAdapter adapter;

    /**
     * Creates a builder of OAuth2-enabled Java HttpClients.
     * @param config       A OAuth2 configuration.
     * @param baseBuilder  A HttpClient builder to use as a starting point.
     */
    public static HttpClient.Builder newBuilder(OAuth2Config config, HttpClient.Builder baseBuilder) {
        return new Builder(config, baseBuilder);
    }

    /**
     * Creates a builder of OAuth2-enabled Java HttpClients.
     * @param config   A OAuth2 configuration.
     */
    public static HttpClient.Builder newBuilder(OAuth2Config config) {
        return new Builder(config);
    }

    private OAuth2HttpClient(OAuth2Config config, HttpClient.Builder baseBuilder) {
        this.handler = new OAuth2Handler(config);
        this.delegate = baseBuilder.build();
        this.adapter = new JavaHttpAdapter(delegate);
    }

    @SuppressWarnings("unchecked") // Type is preserved through the adapter
    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) throws IOException {
        try {
            return (HttpResponse<T>) handler.execute(new JavaRequestContext(request, bodyHandler), adapter).response();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to execute request", e);
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        throw new UnsupportedOperationException("Async version with OAuth2 not implemented");
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request,
        HttpResponse.BodyHandler<T> responseBodyHandler,
        HttpResponse.PushPromiseHandler<T> pushPromiseHandler
    ) {
        throw new UnsupportedOperationException("Async version with OAuth2 not implemented");
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public WebSocket.Builder newWebSocketBuilder() {
        return delegate.newWebSocketBuilder();
    }

    public record Builder(OAuth2Config config, HttpClient.Builder delegate) implements HttpClient.Builder {
        public Builder(OAuth2Config config) {
            this(config, HttpClient.newBuilder());
        }

        @Override
        public HttpClient build() {
            return new OAuth2HttpClient(config, delegate);
        }

        @Override
        public Builder version(Version version) {
            delegate.version(version);
            return this;
        }

        @Override
        public Builder priority(int priority) {
            delegate.priority(priority);
            return this;
        }

        @Override
        public Builder followRedirects(Redirect policy) {
            delegate.followRedirects(policy);
            return this;
        }

        @Override
        public Builder connectTimeout(Duration duration) {
            delegate.connectTimeout(duration);
            return this;
        }

        @Override
        public Builder proxy(ProxySelector proxySelector) {
            delegate.proxy(proxySelector);
            return this;
        }

        @Override
        public Builder authenticator(Authenticator authenticator) {
            delegate.authenticator(authenticator);
            return this;
        }

        @Override
        public Builder executor(Executor executor) {
            delegate.executor(executor);
            return this;
        }

        @Override
        public Builder sslContext(SSLContext sslContext) {
            delegate.sslContext(sslContext);
            return this;
        }

        @Override
        public Builder sslParameters(SSLParameters sslParameters) {
            delegate.sslParameters(sslParameters);
            return this;
        }

        @Override
        public Builder cookieHandler(CookieHandler cookieHandler) {
            delegate.cookieHandler(cookieHandler);
            return this;
        }
    }
}
