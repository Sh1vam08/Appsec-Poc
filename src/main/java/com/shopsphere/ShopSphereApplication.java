package com.shopsphere;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

/**
 * Enterprise AppSec Benchmark Suite — Main Application Entry Point
 *
 * <p>This application is an intentionally vulnerable Spring Boot application
 * designed for evaluating Application Security (AppSec) scanning platforms.
 *
 * <p><strong>WARNING:</strong> This application contains REAL security vulnerabilities.
 * It MUST NEVER be deployed to production or exposed to public networks.
 * Only use in isolated, controlled environments for AppSec tool evaluation.
 *
 * <p>Benchmark Categories:
 * <ul>
 *   <li>SAST: ~80 scenarios (BENCH-SAST-001 to BENCH-SAST-080)</li>
 *   <li>SCA:  ~40 scenarios (BENCH-SCA-001  to BENCH-SCA-040)</li>
 *   <li>DAST: ~20 scenarios (BENCH-DAST-001 to BENCH-DAST-020)</li>
 *   <li>Secrets: ~30 scenarios (BENCH-SECRET-001 to BENCH-SECRET-030)</li>
 *   <li>Container: ~20 scenarios (BENCH-CONTAINER-001 to BENCH-CONTAINER-020)</li>
 *   <li>IaC: ~20 scenarios (BENCH-IAC-001 to BENCH-IAC-020)</li>
 * </ul>
 *
 * @version 1.0.0-BENCHMARK
 */
@SpringBootApplication
public class ShopSphereApplication {

    private static final Logger logger = LoggerFactory.getLogger(ShopSphereApplication.class);

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(ShopSphereApplication.class);
        app.run(args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady(ApplicationReadyEvent event) {
        Environment env = event.getApplicationContext().getEnvironment();
        String port = env.getProperty("server.port", "8080");
        String profile = String.join(", ", env.getActiveProfiles());

        logger.warn("=================================================================");
        logger.warn("  ENTERPRISE APPSEC BENCHMARK SUITE v1.0.0-BENCHMARK");
        logger.warn("=================================================================");
        logger.warn("  *** WARNING: INTENTIONALLY VULNERABLE APPLICATION ***");
        logger.warn("  *** DO NOT DEPLOY TO PRODUCTION ENVIRONMENTS       ***");
        logger.warn("  *** FOR APPSEC TOOL EVALUATION ONLY                ***");
        logger.warn("=================================================================");
        logger.info("  Active Profile : {}", profile.isEmpty() ? "default" : profile);
        logger.info("  Server Port    : {}", port);
        logger.info("  Swagger UI     : http://localhost:{}/swagger-ui.html", port);
        logger.info("  API Docs       : http://localhost:{}/v3/api-docs", port);
        logger.info("  Health         : http://localhost:{}/actuator/health", port);
        logger.info("  E-Commerce APIs : http://localhost:{}/api/v1/", port);
        logger.warn("=================================================================");
        logger.warn("  Total Benchmark Scenarios: 210");
        logger.warn("    SAST: 80  | SCA: 40  | DAST: 20");
        logger.warn("    Secrets: 30 | Container: 20 | IaC: 20");
        logger.warn("=================================================================");
    }
}
