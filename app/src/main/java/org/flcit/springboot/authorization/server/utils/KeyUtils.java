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

package org.flcit.springboot.authorization.server.utils;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @since 
 * @author Florian Lestic
 */
public final class KeyUtils {

    private static final Logger LOG = LoggerFactory.getLogger(KeyUtils.class);

    private static final String ALGORITHM = "RSA";
    private static final int ALGORITHM_SIZE = 2048;

    private static final String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8gY8h9h4glwJft4avuwjGQ6C1J6fk9rejMVb6N8a/GE6sNUVw6t7rYO+ECdnrtQc2Dro3J1JcLq0V1RHi+gb1wEadbdMbAbjlBLKsGvgNhuHsNCiQ9uqDM+sEhr2lU3K8vl/VSnKqEDCiH0OjmcIDWBhCcbQTcvLHjDQPzZQR7Dh0AQ9JkyF15p50ZJ1Ax8eXuygnMN50pULbkK1mYPSeOjMp+TdXStpOE3pSW+zyGOFjsPOCxZTMH2XIXpuVSSO28rTzrP59Z5OZEkR76DRw7N/WQcgEF4PFI456qub1AWypLM7cMULYnuEFB/d2ZB1UjiC5gwqFes047inN9oKrAgMBAAECggEAFclpmBTAhaa+ZP6qp+vXh0awr89OBdYIAmoE8fV5WIPAMAIWLQdQTWcON7YFxErPcw1/szktuS7B3XibUR7xp/yZjL9xOzlXO8zvs5mIWtPgj7K1j4+iKhjZjFPgXlfHNo5QODAbEZG+dTZk1GdEd6t6Xk+S7v6Flc+cAsmRWALAsLXJf+O++LHLl9lcFVfkRY63l2tsc7VeUgZ30ru7GAM9HUEcpchrfvM/KadEb3PbVgznU4XihtbD26mawOo8roaPdQNhcmuah/RUBuoL7ZDqI34E3eJxRN1pka7slRxfPSR+Kr08yYKXclV/CQqYZLrpngnEs0iTY2FpdiGLAQKBgQD0SaRbcwio7AOWUx77pNdmWkAVUTAjr6oDmn3mnegodkgC/fZCWZ7nUIMLRX0WIKlxgU2IYg7XlPrzVM5OHsrhwQEQ6WlhpBFkC2m48HcD9x7+yC2bTkS1xKN4lepr4NJ9flH9jevMlFBekEX+PfYEm6GlIcaCK5j1XfxMW0i7AQKBgQDFi0K40TWga/vc/9Sy6BpNSM2nK0YR2DOR4ERp1TY0g8v1cuT3BbaWBISvcCc/XRPAU2ZC+oyXgbCmWaASb0cYwKdfAYhtDInQMQHJzwBG4Trv5TH9KQdwdOj6h/pIWPI0fF3kI9vK+N/f5GBR2nfiGCwHBsP1xOSb2Vzw8p6ZqwKBgB0+68RfAzxl9Q/8J4ts8rS4PU/QBnlfQHVp+4SuhurBLmHdUawj2phK1UV2LkGF64NBPa0EQE6i8WBMWN6VZSid2KjTqOAdqk9V5nRTpYv9++H4ySz8s9EnF4MKP6RmqAyKIPrAEOjPIMgRca+8b0Wh9Do2zvMqkQdfFyN1EkIBAoGAJruhf3911liV78UxvUqJLbIisK5pdMJBik7A20d082MMMLowbsbuAAguw/9nkqL7ZnBz0poxytsg+d0E59htxkqwBo7UYx1cQDf7s8gks8EhvzvfS1YqIUCrFcRnrJvUEbp45mypgei+bLXotOPzMZ+vskj/T0cl0/EQqiXINzUCgYEAi14Mvm+SZjZ1aIeqxsZ8OJJ5HezDV/2pKa0zuhqUGQRVKZeCkT2Q7GxGQQ+Ek24+nD1B9iupQmC7o3e433MGjL6KS/CspRx+/MTKxe+sUwpoXr64sCk+wfGd7qPA9T2r/l8GHd+/ZwwjzUvdj5esHS3vCIQ4UAHvd1XzvwKyGNk=";
    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvIGPIfYeIJcCX7eGr7sIxkOgtSen5Pa3ozFW+jfGvxhOrDVFcOre62DvhAnZ67UHNg66NydSXC6tFdUR4voG9cBGnW3TGwG45QSyrBr4DYbh7DQokPbqgzPrBIa9pVNyvL5f1UpyqhAwoh9Do5nCA1gYQnG0E3Lyx4w0D82UEew4dAEPSZMhdeaedGSdQMfHl7soJzDedKVC25CtZmD0njozKfk3V0raThN6Ulvs8hjhY7DzgsWUzB9lyF6blUkjtvK086z+fWeTmRJEe+g0cOzf1kHIBBeDxSOOeqrm9QFsqSzO3DFC2J7hBQf3dmQdVI4guYMKhXrNOO4pzfaCqwIDAQAB";
    public static final PublicKey JWKS_PUBLIC_KEY = generateKeyPairRSA().getPublic();

    private static final KeyPair KeyPair_RSA;
    public static final String KID = "542016d4-7e44-40a1-9a59-356c021379e2";

    private KeyUtils() { }

    static {
        try {
            final KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
            KeyPair_RSA = new KeyPair(
                    fact.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY))),
                    fact.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY)))
            );
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair getKeyPairRSA() {
        return KeyPair_RSA;
    }

    private static KeyPair generateKeyPairRSA() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(ALGORITHM_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void printNewKeyPairRSA() {
        final KeyPair keyPair = generateKeyPairRSA();
        LOG.info(keyPair.getPrivate().getFormat());
        LOG.info(keyPair.getPublic().getFormat());
        if (LOG.isInfoEnabled()) {
            LOG.info(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            LOG.info(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        }
    }

}
