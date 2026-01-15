package com.mastercard.developer.oauth2.test.mocks;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.mastercard.developer.oauth2.http.StandardHttpHeader.*;

import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.common.Json;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.HttpHeader;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.mastercard.developer.oauth2.test.helpers.JwsUtils;
import com.nimbusds.jwt.SignedJWT;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.extension.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fake authorization server.
 * Wrapper around WireMockExtension that can be registered as a JUnit extension.
 */
public class FakeAuthorizationServer implements BeforeAllCallback, AfterAllCallback, ParameterResolver {

    private static final Logger logger = LoggerFactory.getLogger(FakeAuthorizationServer.class);

    private final WireMockExtension delegate;
    private final AccessTokenRequestTransformer accessTokenRequestTransformer;

    public FakeAuthorizationServer() {
        this.accessTokenRequestTransformer = new AccessTokenRequestTransformer();
        this.delegate = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort().extensions(accessTokenRequestTransformer)).build();
    }

    /**
     * Simulates a nominal scenario where access token requests succeed.
     * <ul>
     *   <li>Validates the presence and format of required headers (Content-Type, Accept, DPoP, User-Agent)</li>
     *   <li>Validates client_id, client_assertion, and scope in the request body</li>
     *   <li>Verifies the client assertion JWT has the expected kid, sub, and iss claims</li>
     *   <li>Verifies the DPoP proof signature is valid</li>
     *   <li>Expects a nonce claim in the DPoP proof matching the server's current nonce</li>
     *   <li>Returns HTTP 400 with DPoP-Nonce header if nonce is missing or doesn't match</li>
     *   <li>Returns HTTP 200 with access token, DPoP-Nonce header, and token metadata on success</li>
     *   <li>Checks for duplicate headers and rejects requests with duplicates</li>
     * </ul>
     */
    public void useNominalScenario() {
        this.stubFor(post(urlEqualTo("/oauth/token")).willReturn(aResponse().withTransformers(accessTokenRequestTransformer.getName())));
    }

    /**
     * Simulates an error caused by a client assertion signed with an unknown client key.
     */
    public void useInvalidClientAssertionScenario() {
        this.stubFor(
            post(urlEqualTo("/oauth/token")).willReturn(
                aResponse().withStatus(400).withBody("{\"error\":\"invalid_client\",\"error_description\":\"client_assertion signature couldn't be verified\"}")
            )
        );
    }

    private class AccessTokenRequestTransformer implements ResponseDefinitionTransformerV2 {

        private static final String EXPECTED_CLIENT_ID = "fake_service_client_id";
        private static final String EXPECTED_KID = "fake_service_kid";
        private static final String ACCESS_TOKEN = "sample_access_token";

        private final String currentNonce = UUID.randomUUID().toString();

        @Override
        public ResponseDefinition transform(ServeEvent serveEvent) {
            try {
                return _transform(serveEvent);
            } catch (Exception ex) {
                logger.error(ex.getMessage());
                return new ResponseDefinitionBuilder()
                    .withStatus(500)
                    .withHeader(CONTENT_TYPE.value(), "application/json")
                    .withBody(Json.write(Map.of("error", "authorization_server_error")))
                    .build();
            }
        }

        private ResponseDefinition _transform(ServeEvent serveEvent) throws Exception {
            // Get request params
            Request request = serveEvent.getRequest();
            logger.info("Incoming request payload: {}", request.getBodyAsString());
            logger.info("Incoming request headers: {}", request.getHeaders());
            for (HttpHeader header : request.getHeaders().all()) {
                String headerKey = header.key();
                if ((headerKey.equalsIgnoreCase(DPOP.value()) || headerKey.equalsIgnoreCase(USER_AGENT.value())) && header.values() != null && header.values().size() > 1) {
                    throw new IllegalStateException("Duplicate header: " + header.key());
                }
            }
            String contentType = request.getHeader(CONTENT_TYPE.value());
            if (!"application/x-www-form-urlencoded".equals(contentType)) {
                throw new IllegalStateException("\"application/x-www-form-urlencoded\" is expected for the %s header!".formatted(CONTENT_TYPE.value()));
            }
            String accept = request.getHeader(ACCEPT.value());
            if (!"application/json".equals(accept)) {
                throw new IllegalStateException("\"application/json\" is expected for the %s header!".formatted(ACCEPT.value()));
            }
            Map<String, String> params = parseForm(request);
            String clientAssertion = params.get("client_assertion");
            if (clientAssertion == null) {
                throw new IllegalStateException("Missing client assertion");
            }
            String scope = params.get("scope");
            if (scope == null) {
                throw new IllegalStateException("Missing scope");
            }
            String clientId = params.get("client_id");
            if (!EXPECTED_CLIENT_ID.equals(clientId)) {
                throw new IllegalStateException("Invalid client_id in payload");
            }
            String dpopProof = request.getHeader(DPOP.value());
            if (dpopProof == null) {
                throw new IllegalStateException("Missing DPoP proof");
            }
            String userAgent = request.getHeader(USER_AGENT.value());
            if (userAgent == null || !userAgent.contains("Mastercard-OAuth2-Client")) {
                throw new IllegalStateException("User agent is missing or unexpected");
            }

            // Parse/verify JWTs
            SignedJWT clientAssertionJwt = SignedJWT.parse(clientAssertion);
            String kid = clientAssertionJwt.getHeader().getKeyID();
            if (!EXPECTED_KID.equals(kid)) {
                throw new IllegalStateException("Unexpected kid in client assertion");
            }
            String sub = clientAssertionJwt.getJWTClaimsSet().getSubject();
            String iss = clientAssertionJwt.getJWTClaimsSet().getIssuer();
            if (!EXPECTED_CLIENT_ID.equals(sub) || !EXPECTED_CLIENT_ID.equals(iss)) {
                throw new IllegalStateException("Unexpected sub or iss in client assertion");
            }
            List<String> aud = clientAssertionJwt.getJWTClaimsSet().getAudience();
            if (!List.of(FakeAuthorizationServer.this.baseUrl()).equals(aud)) {
                throw new IllegalStateException("Unexpected aud in client assertion");
            }

            SignedJWT dpopJwt = SignedJWT.parse(dpopProof);
            JwsUtils.checkSignatureValid(dpopJwt);

            // Check nonce claim inside the DPoP
            Object providedNonce = dpopJwt.getJWTClaimsSet().getClaim("nonce");
            if (providedNonce == null || !currentNonce.equals(providedNonce.toString())) {
                // Return DPoP-Nonce header with HTTP 400
                logger.info("use_dpop_nonce error. Provided: {}, returning: {}", providedNonce, currentNonce);
                return new ResponseDefinitionBuilder()
                    .withStatus(400)
                    .withHeader(CONTENT_TYPE.value(), "application/json")
                    .withHeader(DPOP_NONCE.value(), currentNonce)
                    .withBody(Json.write(Map.of("error", "use_dpop_nonce")))
                    .build();
            }

            // Return access token
            String tokenJson = Json.write(Map.of("access_token", ACCESS_TOKEN, "token_type", "DPoP", "expires_in", 900, "scope", scope));
            return new ResponseDefinitionBuilder()
                .withStatus(200)
                .withHeader(CONTENT_TYPE.value(), "application/json")
                .withHeader(DPOP_NONCE.value(), currentNonce)
                .withBody(tokenJson)
                .build();
        }

        @Override
        public String getName() {
            return "AccessTokenRequestTransformer";
        }

        @Override
        public boolean applyGlobally() {
            return false;
        }
    }

    @Override
    public void beforeAll(@NotNull ExtensionContext context) throws Exception {
        delegate.beforeAll(context);
    }

    @Override
    public void afterAll(@NotNull ExtensionContext context) throws Exception {
        delegate.afterAll(context);
    }

    @Override
    public boolean supportsParameter(@NotNull ParameterContext parameterContext, @NotNull ExtensionContext extensionContext) throws ParameterResolutionException {
        return delegate.supportsParameter(parameterContext, extensionContext);
    }

    @Override
    public Object resolveParameter(@NotNull ParameterContext parameterContext, @NotNull ExtensionContext extensionContext) throws ParameterResolutionException {
        return delegate.resolveParameter(parameterContext, extensionContext);
    }

    public String baseUrl() {
        return delegate.baseUrl();
    }

    public void stubFor(MappingBuilder mappingBuilder) {
        delegate.stubFor(mappingBuilder);
    }

    public void reset() {
        delegate.resetAll();
    }

    private static Map<String, String> parseForm(Request request) {
        Map<String, String> params = new HashMap<>();
        String body = request.getBodyAsString();

        if (body == null || body.isEmpty()) {
            return params;
        }

        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            params.put(key, value);
        }
        return params;
    }
}
