package com.shopsphere.config;

import com.shopsphere.support.SupportChatHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * Configuration for WebSocket benchmark scenarios.
 * BENCH-DAST-104: Cross-Site WebSocket Hijacking (CSWSH)
 */
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final SupportChatHandler supportChatHandler;

    public WebSocketConfig(SupportChatHandler supportChatHandler) {
        this.supportChatHandler = supportChatHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        // BENCH-DAST-104
        // Vulnerable: Allows connections from any origin (*) and lacks authentication checks.
        registry.addHandler(supportChatHandler, "/ws/support")
                .setAllowedOrigins("*"); 
    }
}
