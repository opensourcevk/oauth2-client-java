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
import com.github.tomakehurst.wiremock.http.RequestMethod;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.mastercard.developer.oauth2.test.helpers.JwsUtils;
import com.nimbusds.jwt.SignedJWT;
import java.util.Map;
import java.util.UUID;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.extension.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fake resource server.
 * Wrapper around WireMockExtension that can be registered as a JUnit extension.
 */
public class FakeResourceServer implements BeforeAllCallback, AfterAllCallback, ParameterResolver {

    private static final Logger logger = LoggerFactory.getLogger(FakeResourceServer.class);

    private final WireMockExtension delegate;
    private final ResourceRequestTransformer resourceRequestTransformer;

    public FakeResourceServer() {
        this.resourceRequestTransformer = new ResourceRequestTransformer();
        this.delegate = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort().extensions(resourceRequestTransformer)).build();
    }

    /**
     * Simulates a nominal scenario where resource requests succeed.
     * <ul>
     *   <li>Validates the presence of required headers (Authorization, DPoP, User-Agent, Accept, Content-Type)</li>
     *   <li>Verifies the Authorization header contains the expected DPoP access token</li>
     *   <li>Verifies the DPoP proof signature is valid</li>
     *   <li>Validates the ath (access token hash) claim in the DPoP proof matches the expected value</li>
     *   <li>Expects a nonce claim in the DPoP proof matching the server's current nonce</li>
     *   <li>Returns HTTP 401 with WWW-Authenticate and DPoP-Nonce headers if nonce is missing or doesn't match</li>
     *   <li>Returns HTTP 200/204 with DPoP-Nonce header and resource data on success</li>
     *   <li>Checks for duplicate headers and rejects requests with duplicates</li>
     * </ul>
     */
    public void useNominalScenario() {
        this.stubFor(post(urlEqualTo("/api/resources")).willReturn(aResponse().withTransformers(resourceRequestTransformer.getName())));
        this.stubFor(get(urlEqualTo("/api/resources/1")).willReturn(aResponse().withTransformers(resourceRequestTransformer.getName())));
        this.stubFor(delete(urlEqualTo("/api/resources/1")).willReturn(noContent().withTransformers(resourceRequestTransformer.getName())));
    }

    /**
     * Simulates an error caused by an access token not having the proper scopes.
     */
    public void useInsufficientScopeScenario() {
        this.stubFor(
            post(urlPathMatching(".*")).willReturn(
                aResponse()
                    .withStatus(403)
                    .withHeader(WWW_AUTHENTICATE.value(), "Dpop error:\"insufficient_scope\", error_description:\"requested scope is not permitted\", algs:\"ES256 PS256\"")
                    .withBody("{\"error\":\"insufficient_scope\",\"error_description\":\"requested scope is not permitted\"}")
            )
        );
    }

    private static class ResourceRequestTransformer implements ResponseDefinitionTransformerV2 {

        private final String currentNonce = UUID.randomUUID().toString();
        private static final String ACCESS_TOKEN = "sample_access_token";
        private static final String EXPECTED_ATH = "bvfMxCVzmPZ0NTqtpvm0_13Jq7zDrBLZYawDcKVGN34";

        @Override
        public ResponseDefinition transform(ServeEvent serveEvent) {
            try {
                return _transform(serveEvent);
            } catch (Exception ex) {
                logger.error(ex.getMessage());
                return new ResponseDefinitionBuilder()
                    .withStatus(500)
                    .withHeader(CONTENT_TYPE.value(), "application/json")
                    .withBody(Json.write(Map.of("error", "resource_server_error")))
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
                if (
                    (headerKey.equalsIgnoreCase(AUTHORIZATION.value()) || headerKey.equalsIgnoreCase(DPOP.value()) || headerKey.equalsIgnoreCase(USER_AGENT.value())) &&
                    header.values() != null &&
                    header.values().size() > 1
                ) {
                    throw new IllegalStateException("Duplicate header: " + header.key());
                }
            }
            String dpopProof = request.getHeader(DPOP.value());
            if (dpopProof == null) {
                throw new IllegalStateException("Missing DPoP proof");
            }
            String authorizationHeader = request.getHeader(AUTHORIZATION.value());
            if (authorizationHeader == null) {
                throw new IllegalStateException("Missing Authorization header");
            }
            if (!ACCESS_TOKEN.equals(authorizationHeader.replaceAll("DPoP ", ""))) {
                throw new IllegalStateException("Unexpected access token");
            }
            String userAgent = request.getHeader(USER_AGENT.value());
            if (userAgent == null || !userAgent.contains("Mastercard-OAuth2-Client")) {
                throw new IllegalStateException("User agent is missing or unexpected");
            }
            String accept = request.getHeader(ACCEPT.value());
            if (!"application/json".equals(accept) && (request.getMethod() == RequestMethod.GET || request.getMethod() == RequestMethod.DELETE)) {
                throw new IllegalStateException("\"application/json\" is expected for the %s header!".formatted(ACCEPT.value()));
            }
            String contentType = request.getHeader(CONTENT_TYPE.value());
            if (!"application/json".equals(contentType) && request.getMethod() == RequestMethod.POST) {
                throw new IllegalStateException("\"application/json\" is expected for the %s header!".formatted(CONTENT_TYPE.value()));
            }

            // Parse/verify JWTs
            SignedJWT dpopJwt = SignedJWT.parse(dpopProof);
            JwsUtils.checkSignatureValid(dpopJwt);
            String ath = (String) dpopJwt.getJWTClaimsSet().getClaim("ath");
            if (!EXPECTED_ATH.equals(ath)) {
                throw new IllegalStateException("Unexpected ath in client assertion");
            }

            // Check nonce claim inside the DPoP
            Object providedNonce = dpopJwt.getJWTClaimsSet().getClaim("nonce");
            if (providedNonce == null || !currentNonce.equals(providedNonce.toString())) {
                // Return DPoP-Nonce header with HTTP 401
                logger.info("use_dpop_nonce error. Provided: {}, returning: {}", providedNonce, currentNonce);
                return new ResponseDefinitionBuilder()
                    .withStatus(401)
                    .withHeader(WWW_AUTHENTICATE.value(), "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\"")
                    .withHeader(DPOP_NONCE.value(), currentNonce)
                    .build();
            }

            // Return OK
            String success = Json.write(Map.of("id", "1"));
            return new ResponseDefinitionBuilder()
                .withStatus(serveEvent.getResponseDefinition().getStatus())
                .withHeader(DPOP_NONCE.value(), currentNonce)
                .withHeader(CONTENT_TYPE.value(), "application/json")
                .withBody(success)
                .build();
        }

        @Override
        public String getName() {
            return "ResourceRequestTransformer";
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
}
