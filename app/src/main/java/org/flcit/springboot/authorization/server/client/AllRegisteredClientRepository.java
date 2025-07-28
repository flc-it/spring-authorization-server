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

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 
 * @since 
 * @author Florian Lestic
 */
public final class AllRegisteredClientRepository implements RegisteredClientRepository {

    private final Map<String, RegisteredClient> idRegistrationMap;

    private final Map<String, RegisteredClient> clientIdRegistrationMap;

    /**
     * Constructs an {@code InMemoryRegisteredClientRepository} using the provided
     * parameters.
     * @param registrations the client registration(s)
     */
    public AllRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));
    }

    /**
     * Constructs an {@code InMemoryRegisteredClientRepository} using the provided
     * parameters.
     * @param registrations the client registration(s)
     */
    public AllRegisteredClientRepository(List<RegisteredClient> registrations) {
        ConcurrentHashMap<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
        for (RegisteredClient registration : registrations) {
            Assert.notNull(registration, "registration cannot be null");
            assertUniqueIdentifiers(registration, idRegistrationMapResult);
            idRegistrationMapResult.put(registration.getId(), registration);
            clientIdRegistrationMapResult.put(registration.getClientId(), registration);
        }
        this.idRegistrationMap = idRegistrationMapResult;
        this.clientIdRegistrationMap = clientIdRegistrationMapResult;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        if (!this.idRegistrationMap.containsKey(registeredClient.getId())) {
            assertUniqueIdentifiers(registeredClient, this.idRegistrationMap);
        }
        this.idRegistrationMap.put(registeredClient.getId(), registeredClient);
        this.clientIdRegistrationMap.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.idRegistrationMap.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return this.clientIdRegistrationMap.computeIfAbsent(clientId, clientIdToCreate -> newRegisteredClient(RegisteredClient.withId(clientIdToCreate).clientId(clientId)));
    }

    private RegisteredClient newRegisteredClient(RegisteredClient.Builder registeredClient) {
        return registeredClient
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(
                        ClientSettings.builder()
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                        .build()
                )
                .tokenSettings(
                        TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build()
                 )
                .build();
    }

    private void assertUniqueIdentifiers(RegisteredClient registeredClient,
            Map<String, RegisteredClient> registrations) {
        registrations.values().forEach(registration -> {
            if (registeredClient.getId().equals(registration.getId())) {
                throw new IllegalArgumentException("Registered client must be unique. " + "Found duplicate identifier: "
                        + registeredClient.getId());
            }
            if (registeredClient.getClientId().equals(registration.getClientId())) {
                throw new IllegalArgumentException("Registered client must be unique. "
                        + "Found duplicate client identifier: " + registeredClient.getClientId());
            }
            if (StringUtils.hasText(registeredClient.getClientSecret())
                    && registeredClient.getClientSecret().equals(registration.getClientSecret())) {
                throw new IllegalArgumentException("Registered client must be unique. "
                        + "Found duplicate client secret for identifier: " + registeredClient.getId());
            }
        });
    }

}
