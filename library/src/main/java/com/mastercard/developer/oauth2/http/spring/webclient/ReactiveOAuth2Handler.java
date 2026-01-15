package com.mastercard.developer.oauth2.http.spring.webclient;

import com.mastercard.developer.oauth2.config.OAuth2Config;
import com.mastercard.developer.oauth2.core.OAuth2Handler;
import com.mastercard.developer.oauth2.http.HttpAdapter;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * A reactive wrapper around {@link OAuth2Handler} that provides non-blocking operations.
 * This handler executes OAuth2 operations on a bounded elastic scheduler to avoid
 * blocking reactive pipelines.
 */
@SuppressWarnings("squid:S00119") // For readability, we keep generic type names as 'Request' and 'Response'
final class ReactiveOAuth2Handler {

    private final OAuth2Handler handler;

    /**
     * Creates a new reactive OAuth2 handler.
     */
    public ReactiveOAuth2Handler(OAuth2Config config) {
        this.handler = new OAuth2Handler(config);
    }

    /**
     * Executes the OAuth2 flow reactively.
     */
    public <Request, Response> Mono<Response> execute(Request request, ReactiveHttpAdapter<Request, Response> adapter) {
        return Mono.fromCallable(() -> handler.execute(request, adapter.toBlockingAdapter())).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Interface for reactive HTTP adapters.
     */
    public interface ReactiveHttpAdapter<Request, Response> {
        /**
         * Converts this reactive adapter to a blocking adapter for use with {@link OAuth2Handler}.
         */
        HttpAdapter<Request, Response> toBlockingAdapter();
    }
}
