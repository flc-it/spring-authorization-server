package org.flcit.springboot.authorization.server;

import org.springframework.test.context.junit.jupiter.EnabledIf;

@EnabledIf("${dev.tests.enabled}")
public abstract class SpringBootBaseDevTest extends SpringBootBaseTest {

}