package com.shopsphere.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.core.annotation.Order;

/**
 * Configuration to deliberately disable default security headers.
 * This is used to test SAST capability for "Misconfiguration detection" (Passive).
 */
@Configuration
public class SecurityHeadersConfig {

    @Bean
    @Order(100) // Execute after primary auth configs
    public SecurityFilterChain headerFilterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.disable()) // Vulnerable to Clickjacking
                .xssProtection(xssProtection -> xssProtection.disable()) // Disables browser XSS protection
                .httpStrictTransportSecurity(hsts -> hsts.disable()) // Disables HSTS
            );
        return http.build();
    }
}
