package com.mastercard.developer.oauth2.http.apache;

import static com.mastercard.developer.oauth2.http.apache.ApacheHttpAdapter.ApacheRequestContext;

import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import java.net.URI;
import java.net.URL;
import java.util.Optional;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.entity.BufferedHttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;

/**
 * Internal adapter for Apache HttpClient.
 */
record ApacheHttpAdapter(CloseableHttpClient delegate) implements HttpAdapter<ApacheRequestContext, CloseableHttpResponse> {
    record ApacheRequestContext(HttpHost target, ClassicHttpRequest request, HttpContext context) {}

    @Override
    public String getMethod(ApacheRequestContext request) {
        return request.request().getMethod();
    }

    @Override
    public URL getUrl(ApacheRequestContext request) throws Exception {
        return URI.create(request.target().toString() + request.request().getRequestUri()).toURL();
    }

    @Override
    public CloseableHttpResponse sendAccessTokenRequest(ApacheRequestContext resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) throws Exception {
        var requestBuilder = ClassicRequestBuilder.post(tokenUrl.toURI()).setEntity(new StringEntity(formBody, ContentType.APPLICATION_FORM_URLENCODED));
        headers.forEach(header -> requestBuilder.addHeader(header.name(), header.value()));
        return CloseableHttpResponse.adapt(delegate.executeOpen(null, requestBuilder.build(), resourceRequest.context()));
    }

    @Override
    public CloseableHttpResponse sendResourceRequest(ApacheRequestContext request, HttpHeaders headers) throws Exception {
        String resourceUrl = request.target().toString() + request.request().getRequestUri();
        var requestBuilder = ClassicRequestBuilder.copy(request.request()).setUri(URI.create(resourceUrl));
        // Add or replace HTTP headers in the original request
        headers.forEach(header -> {
            requestBuilder.removeHeaders(header.name());
            requestBuilder.addHeader(header.name(), header.value());
        });
        return CloseableHttpResponse.adapt(delegate.executeOpen(request.target(), requestBuilder.build(), request.context()));
    }

    @Override
    public int getStatusCode(CloseableHttpResponse response) {
        return response.getCode();
    }

    @Override
    public Optional<String> getHeader(CloseableHttpResponse response, String name) {
        Header header = response.getFirstHeader(name);
        return Optional.ofNullable(header != null ? header.getValue() : null);
    }

    @Override
    public Optional<String> readBody(CloseableHttpResponse response) throws Exception {
        var entity = response.getEntity();
        if (entity == null) {
            return Optional.empty();
        }
        if (!entity.isRepeatable()) {
            response.setEntity(new BufferedHttpEntity(entity));
        }
        return Optional.of(EntityUtils.toString(response.getEntity()));
    }

    @Override
    public void close(CloseableHttpResponse response) {
        try {
            response.close();
        } catch (Exception ignore) {
            // Ignore
        }
    }
}
