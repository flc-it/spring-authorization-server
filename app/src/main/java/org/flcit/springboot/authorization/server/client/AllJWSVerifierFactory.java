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

import java.security.Key;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.util.Base64URL;

/**
 * 
 * @since 
 * @author Florian Lestic
 */
public final class AllJWSVerifierFactory implements JWSVerifierFactory, JWSVerifier {

    /**
     * The supported JWS algorithms.
     */
    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = new HashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));

    /**
     * The JCA context.
     */
    private final JCAContext jcaContext = new JCAContext();

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

    @Override
    public JWSVerifier createJWSVerifier(JWSHeader header, Key key) throws JOSEException {
        return this;
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        return true;
    }

}
