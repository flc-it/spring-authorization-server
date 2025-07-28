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

package org.flcit.springboot.authorization.server.validators;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * 
 * @since 
 * @author Florian Lestic
 */
public final class TimestampIATValidator implements OAuth2TokenValidator<Jwt> {

    private final Log logger = LogFactory.getLog(getClass());

    private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);

    private final Duration clockSkew;

    private Clock clock = Clock.systemUTC();

    /**
     * A basic instance with the default max clock skew
     */
    public TimestampIATValidator() {
        this(DEFAULT_MAX_CLOCK_SKEW);
    }

    public TimestampIATValidator(Duration clockSkew) {
        Assert.notNull(clockSkew, "clockSkew cannot be null");
        this.clockSkew = clockSkew;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Assert.notNull(jwt, "jwt cannot be null");
        Instant issued = jwt.getIssuedAt();
        if (issued != null && Instant.now(this.clock).minus(this.clockSkew).isAfter(issued)) {
            OAuth2Error oAuth2Error = createOAuth2Error("Token was issued too far in the past to be used now");
            return OAuth2TokenValidatorResult.failure(oAuth2Error);
        }
        return OAuth2TokenValidatorResult.success();
    }

    private OAuth2Error createOAuth2Error(String reason) {
        this.logger.debug(reason);
        return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, reason,
                "https://tools.ietf.org/html/rfc6750#section-3.1");
    }

}
