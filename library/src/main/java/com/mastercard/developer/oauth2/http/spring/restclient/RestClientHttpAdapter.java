package com.mastercard.developer.oauth2.http.spring.restclient;

import static com.mastercard.developer.oauth2.http.spring.restclient.RestClientHttpAdapter.SpringRequestContext;

import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Internal adapter for Spring RestClient.
 */
@SuppressWarnings("NullableProblems") // Spring API nullability varies across versions
record RestClientHttpAdapter() implements HttpAdapter<SpringRequestContext, ClientHttpResponse> {
    record SpringRequestContext(HttpRequest request, String body, ClientHttpRequestExecution execution) {}

    @Override
    public String getMethod(SpringRequestContext context) {
        return context.request().getMethod().name();
    }

    @Override
    public URL getUrl(SpringRequestContext context) throws Exception {
        return context.request().getURI().toURL();
    }

    @Override
    public ClientHttpResponse sendAccessTokenRequest(SpringRequestContext resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) throws Exception {
        var tokenRequest = new HttpRequest() {
            @Override
            public HttpMethod getMethod() {
                return HttpMethod.POST;
            }

            @Override
            public URI getURI() {
                return URI.create(tokenUrl.toString());
            }

            // Keep this without @Override
            // Introduced in Spring Web 6.1.0
            public Map<String, Object> getAttributes() {
                return Map.of();
            }

            @Override
            public org.springframework.http.HttpHeaders getHeaders() {
                var httpHeaders = new org.springframework.http.HttpHeaders();
                headers.forEach(header -> httpHeaders.set(header.name(), header.value()));
                return httpHeaders;
            }
        };
        return new BufferedClientHttpResponse(resourceRequest.execution().execute(tokenRequest, formBody.getBytes()));
    }

    @Override
    public ClientHttpResponse sendResourceRequest(SpringRequestContext request, HttpHeaders headers) throws Exception {
        // Add or replace HTTP headers in the original request
        org.springframework.http.HttpHeaders httpHeaders = request.request().getHeaders();
        headers.forEach(header -> {
            httpHeaders.remove(header.name());
            httpHeaders.set(header.name(), header.value());
        });
        return new BufferedClientHttpResponse(request.execution().execute(request.request(), request.body().getBytes()));
    }

    @Override
    public int getStatusCode(ClientHttpResponse response) throws IOException {
        return response.getStatusCode().value();
    }

    @Override
    public Optional<String> getHeader(ClientHttpResponse response, String name) {
        return Optional.ofNullable(response.getHeaders().getFirst(name));
    }

    @Override
    public Optional<String> readBody(ClientHttpResponse response) throws IOException {
        return Optional.of(new String(response.getBody().readAllBytes()));
    }

    @Override
    public void close(ClientHttpResponse response) {
        response.close();
    }

    private static final class BufferedClientHttpResponse implements ClientHttpResponse {

        private final ClientHttpResponse clientHttpResponse;
        private final byte[] bodyBytes;

        BufferedClientHttpResponse(ClientHttpResponse clientHttpResponse) throws IOException {
            this.clientHttpResponse = clientHttpResponse;
            this.bodyBytes = clientHttpResponse.getBody().readAllBytes();
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return clientHttpResponse.getStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return clientHttpResponse.getStatusText();
        }

        @Override
        public void close() {
            clientHttpResponse.close();
        }

        @Override
        public InputStream getBody() {
            return new ByteArrayInputStream(bodyBytes);
        }

        @Override
        public org.springframework.http.HttpHeaders getHeaders() {
            return clientHttpResponse.getHeaders();
        }
    }
}
