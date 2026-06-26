package com.shopsphere.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuration for CORS benchmark scenarios.
 * BENCH-DAST-107: CORS Misconfiguration (Vulnerable Variant)
 */
@Configuration
public class CorsVulnerableConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // BENCH-DAST-107
        // Vulnerable: Allows any origin to access the API and explicitly allows credentials.
        // This is a highly dangerous configuration that allows cross-origin data theft.
        registry.addMapping("/api/v1/cors/vulnerable/**")
                .allowedOriginPatterns("*") // Spring 5.3+ way to say "allow all origins with credentials"
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
