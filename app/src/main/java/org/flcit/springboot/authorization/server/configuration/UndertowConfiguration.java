package org.flcit.springboot.authorization.server.configuration;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.embedded.undertow.UndertowBuilderCustomizer;
import org.springframework.context.annotation.Configuration;

import io.undertow.Undertow.Builder;

@Configuration
public class UndertowConfiguration implements UndertowBuilderCustomizer {

    private final ServerProperties serverProperties;

    UndertowConfiguration(ServerProperties serverProperties) {
        this.serverProperties = serverProperties;
    }

    @Override
    public void customize(Builder builder) {
        // Default is Runtime.getRuntime().maxMemory() : 0 > false < 64mb > true < 128mb > true
        if (serverProperties.getUndertow().getDirectBuffers() == null) {
            builder.setDirectBuffers(true);
        }
        // Default is Runtime.getRuntime().maxMemory() : 0 > 512 < 64mb > 1024 < 128mb > 1024 * 16 - 20
        if (serverProperties.getUndertow().getBufferSize() == null) {
            builder.setBufferSize(1024 * 16 - 20);
        }
        // Default is Math.max(Runtime.getRuntime().availableProcessors(), 2)
        Integer ioThreads = serverProperties.getUndertow().getThreads().getIo();
        if (ioThreads == null) {
            ioThreads = Runtime.getRuntime().availableProcessors() * 2;
            builder.setIoThreads(ioThreads);
        }
        // Default is ioThreads * 8
        if (serverProperties.getUndertow().getThreads().getWorker() == null) {
            builder.setWorkerThreads(ioThreads * 12);
        }
    }

}
