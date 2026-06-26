package com.shopsphere.support;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Handler for WebSocket benchmark scenarios.
 * BENCH-DAST-105: Command Injection over WebSocket (Vulnerable Variant)
 */
@Component
public class SupportChatHandler extends TextWebSocketHandler {

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        
        // BENCH-DAST-105
        // Vulnerable Sink: Executing commands received over the unauthenticated WebSocket.
        if (payload.startsWith("ping ")) {
            String target = payload.substring(5);
            try {
                // Command Injection vector
                Process process = Runtime.getRuntime().exec("ping -c 1 " + target);
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line = reader.readLine();
                    session.sendMessage(new TextMessage("Ping result: " + line));
                }
            } catch (Exception e) {
                session.sendMessage(new TextMessage("Error executing ping"));
            }
        } else {
            session.sendMessage(new TextMessage("Echo: " + payload));
        }
    }
}
