package com.shopsphere.support;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for Emerging Threats (AI / LLM) benchmark scenarios.
 * BENCH-DAST-102: Prompt Injection (Vulnerable Variant)
 */
@RestController
@RequestMapping("/api/v1/ai")
public class AiAssistantController {

    /**
     * BENCH-DAST-102: Prompt Injection
     * Simulates an LLM integration where user input is blindly concatenated into a system prompt.
     * This acts as a sink for emerging AI-security scanners.
     */
    @PostMapping("/chat")
    public ResponseEntity<String> chatWithAi(@RequestParam String userInput) {
        // BENCH-DAST-102
        
        // Vulnerable: Concatenating untrusted user input directly into an LLM instruction context
        String systemPrompt = "You are a helpful shopping assistant. Only answer questions about products.\n" +
                              "User query: " + userInput;
                              
        // In a real app, this prompt would be sent to OpenAI/Anthropic/etc.
        // Here we simulate the LLM echoing the malicious instruction if Prompt Injection occurs.
        String mockLlmResponse = simulateLlmCall(systemPrompt);
        
        return ResponseEntity.ok(mockLlmResponse);
    }
    
    private String simulateLlmCall(String prompt) {
        // Mocking an LLM executing an injected command for the benchmark
        if (prompt.contains("Ignore previous instructions") || prompt.contains("system prompt")) {
            return "AI: I have ignored previous instructions. How can I assist you with arbitrary tasks?";
        }
        return "AI: I am here to help you shop.";
    }
}
