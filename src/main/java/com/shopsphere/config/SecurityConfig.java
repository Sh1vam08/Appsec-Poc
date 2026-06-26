package com.shopsphere.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Spring Security 6.2 Configuration
 * Configures request authorization, disables CSRF for API endpoints,
 * and allows iframe embedding for the H2 database console.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                // Allow unrestricted access to the H2 console
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                // Allow unrestricted access to Swagger UI and API Docs
                .requestMatchers(new AntPathRequestMatcher("/swagger-ui/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/swagger-ui.html")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/v3/api-docs/**")).permitAll()
                // Allow unrestricted access to Spring Boot Actuator
                .requestMatchers(new AntPathRequestMatcher("/actuator/**")).permitAll()
                // Allow unrestricted access to all API benchmark endpoints
                .requestMatchers(new AntPathRequestMatcher("/api/**")).permitAll()
                // Allow access to standard static resources and pages by default
                .requestMatchers(new AntPathRequestMatcher("/**")).permitAll()
            )
            .headers(headers -> headers
                // Disable X-Frame-Options to allow H2 Console to load in frames
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
            );

        return http.build();
    }

    /**
     * Disable Spring Security's default StrictHttpFirewall blocking of path traversal vectors.
     * Without this, DAST tools cannot legitimately test the Path Traversal vulnerabilities
     * because the framework intercepts requests containing '../' or encoded variants.
     */
    @Bean
    public org.springframework.security.web.firewall.HttpFirewall allowUrlEncodedSlashHttpFirewall() {
        org.springframework.security.web.firewall.StrictHttpFirewall firewall = new org.springframework.security.web.firewall.StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowUrlEncodedDoubleSlash(true);
        firewall.setAllowUrlEncodedPeriod(true);
        firewall.setAllowBackSlash(true);
        firewall.setAllowUrlEncodedPercent(true);
        return firewall;
    }
}
