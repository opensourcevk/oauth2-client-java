package com.mastercard.developer.oauth2.http.okhttp3;

import com.mastercard.developer.oauth2.http.HttpAdapter;
import com.mastercard.developer.oauth2.http.HttpHeaders;
import java.net.URL;
import java.util.Optional;
import okhttp3.*;

/**
 * Internal adapter for OkHttp.
 */
record OkHttpAdapter(OkHttpClient delegate) implements HttpAdapter<Interceptor.Chain, Response> {
    @Override
    public String getMethod(Interceptor.Chain chain) {
        return chain.request().method();
    }

    @Override
    public URL getUrl(Interceptor.Chain chain) {
        return chain.request().url().url();
    }

    @Override
    public Response sendAccessTokenRequest(Interceptor.Chain resourceRequest, URL tokenUrl, String formBody, HttpHeaders headers) throws Exception {
        var headersBuilder = new okhttp3.Headers.Builder();
        headers.forEach(header -> headersBuilder.add(header.name(), header.value()));
        var builder = new Request.Builder().url(tokenUrl).headers(headersBuilder.build()).method("POST", RequestBody.create(formBody.getBytes()));
        return delegate.newCall(builder.build()).execute();
    }

    @Override
    public Response sendResourceRequest(Interceptor.Chain request, HttpHeaders headers) throws Exception {
        Request originalRequest = request.request();
        // Add or replace HTTP headers in the original request
        var headersBuilder = originalRequest.headers().newBuilder();
        headers.forEach(header -> {
            headersBuilder.removeAll(header.name());
            headersBuilder.add(header.name(), header.value());
        });
        return request.proceed(originalRequest.newBuilder().headers(headersBuilder.build()).build());
    }

    @Override
    public int getStatusCode(Response response) {
        return response.code();
    }

    @Override
    public Optional<String> getHeader(Response response, String name) {
        return Optional.ofNullable(response.header(name));
    }

    @Override
    public Optional<String> readBody(Response response) throws Exception {
        var source = response.body().source();
        source.request(Long.MAX_VALUE);
        try (var buffer = source.getBuffer()) {
            return Optional.of(buffer.clone().readUtf8());
        }
    }

    @Override
    public void close(Response response) {
        response.close();
    }
}
