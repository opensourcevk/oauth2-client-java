package com.mastercard.developer.oauth2.http.feign;

import static com.mastercard.developer.oauth2.http.feign.FeignHttpAdapter.FeignRequestContext;

import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import feign.Client;
import feign.Request;
import feign.Response;
import feign.Util;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

/**
 * Internal adapter for Feign Client.
 */
record FeignHttpAdapter(Client delegate) implements HttpAdapter<FeignRequestContext, Response> {
    record FeignRequestContext(Request request, Request.Options options) {}

    @Override
    public String getMethod(FeignRequestContext context) {
        return context.request().httpMethod().name();
    }

    @Override
    public URL getUrl(FeignRequestContext context) throws Exception {
        return URI.create(context.request().url()).toURL();
    }

    @Override
    public Response sendAccessTokenRequest(FeignRequestContext resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) throws Exception {
        var requestHeaders = new LinkedHashMap<String, Collection<String>>();
        headers.forEach(header -> requestHeaders.put(header.name(), List.of(header.value())));
        var tokenRequest = Request.create(Request.HttpMethod.POST, tokenUrl.toString(), requestHeaders, formBody.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8, null);
        return withReusableBody(delegate.execute(tokenRequest, new Request.Options()));
    }

    @Override
    public Response sendResourceRequest(FeignRequestContext request, HttpHeaders headers) throws Exception {
        // Add or replace HTTP headers in the original request
        var originalRequest = request.request();
        var requestHeaders = new LinkedHashMap<>(originalRequest.headers());
        headers.forEach(header -> {
            requestHeaders.remove(header.name());
            requestHeaders.put(header.name(), List.of(header.value()));
        });
        var resourceRequest = Request.create(
            originalRequest.httpMethod(),
            originalRequest.url(),
            requestHeaders,
            originalRequest.body(),
            originalRequest.charset(),
            originalRequest.requestTemplate()
        );
        return withReusableBody(delegate.execute(resourceRequest, request.options()));
    }

    @Override
    public int getStatusCode(Response response) {
        return response.status();
    }

    @Override
    public Optional<String> getHeader(Response response, String name) {
        Collection<String> values = response.headers().get(name);
        if (values == null || values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(values.iterator().next());
    }

    @Override
    public Optional<String> readBody(Response response) throws Exception {
        if (response.body() == null) {
            return Optional.empty();
        }
        return Optional.of(Util.toString(response.body().asReader(StandardCharsets.UTF_8)));
    }

    @Override
    public void close(Response response) {
        if (response.body() != null) {
            Util.ensureClosed(response.body());
        }
    }

    private Response withReusableBody(Response response) throws IOException {
        Response.Body body = response.body();
        if (body == null) {
            return response;
        }
        var bodyString = Util.toString(body.asReader(StandardCharsets.UTF_8));
        return response.toBuilder().body(bodyString, StandardCharsets.UTF_8).build();
    }
}
