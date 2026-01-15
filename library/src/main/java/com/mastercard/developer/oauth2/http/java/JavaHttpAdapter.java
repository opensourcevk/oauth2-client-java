package com.mastercard.developer.oauth2.http.java;

import static com.mastercard.developer.oauth2.http.java.JavaHttpAdapter.*;

import com.mastercard.developer.oauth2.exception.OAuth2ClientException;
import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Flow;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.SSLSession;

/**
 * Internal adapter for Java HttpClient.
 */
record JavaHttpAdapter(HttpClient delegate) implements HttpAdapter<JavaRequestContext, JavaResponseContext> {
    /**
     * Request context holding the {@link HttpRequest} and the body handler to be used for the response.
     */
    record JavaRequestContext(HttpRequest httpRequest, HttpResponse.BodyHandler<?> bodyHandler) {}

    /**
     * Response context holding the internal response with a string response body, and a response
     * adapted to the original {@link HttpResponse.BodyHandler}.
     */
    record JavaResponseContext(HttpResponse<?> internalResponse, HttpResponse<?> response) {}

    @Override
    public String getMethod(JavaRequestContext request) {
        return request.httpRequest().method();
    }

    @Override
    public URL getUrl(JavaRequestContext request) throws Exception {
        return request.httpRequest().uri().toURL();
    }

    @Override
    public JavaResponseContext sendAccessTokenRequest(JavaRequestContext resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) throws Exception {
        var requestBuilder = HttpRequest.newBuilder().uri(tokenUrl.toURI()).POST(HttpRequest.BodyPublishers.ofString(formBody));
        addHeaders(requestBuilder, headers);
        var tokenResponse = delegate.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        HttpResponse<?> actualResponse = new WithTransformedBodyResponse<>(tokenResponse, resourceRequest.bodyHandler());
        return new JavaResponseContext(tokenResponse, actualResponse);
    }

    @Override
    public JavaResponseContext sendResourceRequest(JavaRequestContext request, HttpHeaders headers) throws Exception {
        var originalRequest = request.httpRequest();
        var body = originalRequest.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody());
        var requestBuilder = HttpRequest.newBuilder(originalRequest.uri()).method(originalRequest.method(), body);
        originalRequest
            .headers()
            .map()
            .entrySet()
            .stream()
            .filter(entry -> !headers.contains(entry.getKey()))
            .forEach(entry -> entry.getValue().forEach(value -> requestBuilder.header(entry.getKey(), value)));
        addHeaders(requestBuilder, headers);
        var resourceResponse = delegate.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        HttpResponse<?> actualResponse = new WithTransformedBodyResponse<>(resourceResponse, request.bodyHandler());
        return new JavaResponseContext(resourceResponse, actualResponse);
    }

    @Override
    public int getStatusCode(JavaResponseContext response) {
        return response.internalResponse().statusCode();
    }

    @Override
    public Optional<String> getHeader(JavaResponseContext response, String name) {
        return response.internalResponse().headers().firstValue(name);
    }

    @Override
    public Optional<String> readBody(JavaResponseContext response) throws Exception {
        return readBody(response.internalResponse());
    }

    @Override
    public void close(JavaResponseContext response) {
        // No-op
    }

    private static void addHeaders(HttpRequest.Builder builder, HttpHeaders headers) {
        headers.forEach(header -> builder.header(header.name(), header.value()));
    }

    private static class WithTransformedBodyResponse<T> implements HttpResponse<T> {

        private final HttpResponse<?> originalResponse;
        private final T adaptedBody;

        public WithTransformedBodyResponse(HttpResponse<?> originalResponse, HttpResponse.BodyHandler<T> bodyHandler) throws IOException {
            var responseInfo = new ResponseInfoImpl(originalResponse);
            var subscriber = bodyHandler.apply(responseInfo);
            subscriber.onSubscribe(new NullSubscription());
            String body = readBody(originalResponse).orElse("");
            if (!body.isEmpty()) {
                subscriber.onNext(List.of(ByteBuffer.wrap(body.getBytes(StandardCharsets.UTF_8))));
            }
            subscriber.onComplete();
            this.originalResponse = originalResponse;
            this.adaptedBody = subscriber.getBody().toCompletableFuture().join();
        }

        @Override
        public int statusCode() {
            return originalResponse.statusCode();
        }

        @Override
        public HttpRequest request() {
            return originalResponse.request();
        }

        @Override
        public Optional<HttpResponse<T>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public java.net.http.HttpHeaders headers() {
            return originalResponse.headers();
        }

        @Override
        public T body() {
            return adaptedBody;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return originalResponse.sslSession();
        }

        @Override
        public URI uri() {
            return originalResponse.uri();
        }

        @Override
        public HttpClient.Version version() {
            return originalResponse.version();
        }
    }

    private record ResponseInfoImpl(HttpResponse<?> response) implements HttpResponse.ResponseInfo {
        @Override
        public int statusCode() {
            return response.statusCode();
        }

        @Override
        public java.net.http.HttpHeaders headers() {
            return response.headers();
        }

        @Override
        public HttpClient.Version version() {
            return response.version();
        }
    }

    private record NullSubscription() implements Flow.Subscription {
        @Override
        public void request(long n) {
            // No-op
        }

        @Override
        public void cancel() {
            // No-op
        }
    }

    private static Optional<String> readBody(HttpResponse<?> response) throws IOException {
        var body = response.body();
        if (body == null) return Optional.empty();
        if (body instanceof String bodyString) return Optional.of(bodyString);
        if (body instanceof byte[] bodyBytes) return Optional.of(new String(bodyBytes, StandardCharsets.UTF_8));
        if (body instanceof InputStream bodyInputStream) return Optional.of(new String(bodyInputStream.readAllBytes(), StandardCharsets.UTF_8));
        if (body instanceof Stream<?> bodyStream) return Optional.of(bodyStream.map(Objects::toString).collect(Collectors.joining()));
        if (body instanceof Path bodyPath) return Optional.of(Files.readString(bodyPath));
        throw new OAuth2ClientException("Unsupported body type: " + body.getClass().getName());
    }
}
