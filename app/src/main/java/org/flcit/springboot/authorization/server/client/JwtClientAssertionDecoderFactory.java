/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.flcit.springboot.authorization.server.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;

import org.flcit.springboot.authorization.server.utils.KeyUtils;
import org.flcit.springboot.authorization.server.validators.TimestampIATValidator;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

/**
 * A {@link JwtDecoderFactory factory} that provides a {@link JwtDecoder} for the
 * specified {@link RegisteredClient} and is used for authenticating a {@link Jwt} Bearer
 * Token during OAuth 2.0 Client Authentication.
 *
 * @author Florian Lestic
 * @see JwtDecoderFactory
 * @see RegisteredClient
 * @see OAuth2TokenValidator
 * @see JwtClientAssertionAuthenticationProvider
 * @see ClientAuthenticationMethod#PRIVATE_KEY_JWT
 * @see ClientAuthenticationMethod#CLIENT_SECRET_JWT
 */
public final class JwtClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

    /**
     * The default {@code OAuth2TokenValidator<Jwt>} factory that validates the
     * {@link JwtClaimNames#ISS iss}, {@link JwtClaimNames#SUB sub},
     * {@link JwtClaimNames#IAT iat}, {@link JwtClaimNames#IAT sub},
     * {@link JwtClaimNames#AUD aud}, {@link JwtClaimNames#EXP exp} and
     * {@link JwtClaimNames#NBF nbf} claims of the {@link Jwt} for the specified
     * {@link RegisteredClient}.
     */
    public static final Function<RegisteredClient, OAuth2TokenValidator<Jwt>> DEFAULT_JWT_VALIDATOR_FACTORY = defaultJwtValidatorFactory();

    private static final String JWT_CLIENT_AUTHENTICATION_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-3";

    private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT, null);

    private static final JWSKeySelector<SecurityContext> JWS_KEY_SELECTOR = new SingleKeyJWSKeySelector<>(JWSAlgorithm.RS256, KeyUtils.JWKS_PUBLIC_KEY);

    private static final String MESSAGE = "Failed to find a Signature Verifier for Client: '";

    private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

    private Function<RegisteredClient, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = DEFAULT_JWT_VALIDATOR_FACTORY;

    @Override
    public JwtDecoder createDecoder(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return this.jwtDecoders.computeIfAbsent(registeredClient.getId(), key -> {
            NimbusJwtDecoder jwtDecoder = buildDecoder(registeredClient);
            jwtDecoder.setJwtValidator(this.jwtValidatorFactory.apply(registeredClient));
            return jwtDecoder;
        });
    }

    private static NimbusJwtDecoder buildDecoder(RegisteredClient registeredClient) {
        JwsAlgorithm jwsAlgorithm = registeredClient.getClientSettings()
            .getTokenEndpointAuthenticationSigningAlgorithm();
        if (jwsAlgorithm instanceof SignatureAlgorithm) {
            return new NimbusJwtDecoder(processor());
        }
        OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                MESSAGE + registeredClient.getId()
                        + "'. Check to ensure you have configured a valid JWS Algorithm: '" + jwsAlgorithm + "'.",
                JWT_CLIENT_AUTHENTICATION_ERROR_URI);
        throw new OAuth2AuthenticationException(oauth2Error);
    }

    private static JWTProcessor<SecurityContext> processor() {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSTypeVerifier(JWT_TYPE_VERIFIER);
        jwtProcessor.setJWSKeySelector(JWS_KEY_SELECTOR);
        jwtProcessor.setJWSVerifierFactory(new AllJWSVerifierFactory());
        // Spring Security validates the claim set independent from Nimbus
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        return jwtProcessor;
    }

    private static Function<RegisteredClient, OAuth2TokenValidator<Jwt>> defaultJwtValidatorFactory() {
        return registeredClient -> {
            String clientId = registeredClient.getClientId();
            return new DelegatingOAuth2TokenValidator<>(new JwtClaimValidator<>(JwtClaimNames.ISS, clientId::equals),
                    new JwtClaimValidator<>(JwtClaimNames.SUB, clientId::equals),
                    new JwtClaimValidator<>(JwtClaimNames.AUD, containsAudience()),
                    new JwtClaimValidator<>(JwtClaimNames.EXP, Objects::nonNull),
                    new JwtTimestampValidator(),
                    new TimestampIATValidator()
            );
        };
    }

    private static Predicate<List<String>> containsAudience() {
        return audienceClaim -> {
            if (CollectionUtils.isEmpty(audienceClaim)) {
                return false;
            }
            List<String> audienceList = getAudience();
            for (String audience : audienceClaim) {
                if (audienceList.contains(audience)) {
                    return true;
                }
            }
            return false;
        };
    }

    private static List<String> getAudience() {
        AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
        if (!StringUtils.hasText(authorizationServerContext.getIssuer())) {
            return Collections.emptyList();
        }

        AuthorizationServerSettings authorizationServerSettings = authorizationServerContext
            .getAuthorizationServerSettings();
        List<String> audience = new ArrayList<>();
        audience.add(authorizationServerContext.getIssuer());
        audience.add(asUrl(authorizationServerContext.getIssuer(), authorizationServerSettings.getTokenEndpoint()));
        audience.add(asUrl(authorizationServerContext.getIssuer(),
                authorizationServerSettings.getTokenIntrospectionEndpoint()));
        audience.add(asUrl(authorizationServerContext.getIssuer(),
                authorizationServerSettings.getTokenRevocationEndpoint()));
        audience.add(asUrl(authorizationServerContext.getIssuer(),
                authorizationServerSettings.getPushedAuthorizationRequestEndpoint()));
        return audience;
    }

    private static String asUrl(String issuer, String endpoint) {
        return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
    }

}
