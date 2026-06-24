package com.shopsphere.service.sca;

import org.springframework.stereotype.Service;
import java.io.File;
import java.security.Security;

/**
 * Service for SCA Benchmark Scenarios.
 * Covers BENCH-SCA-001 to BENCH-SCA-040 (direct and transitive reachable/unreachable).
 */
@Service
public class SystemDiagnosticsService {

    /**
     * Log4j Core Reachable API calls
     * BENCH-SCA-001 (Direct) & BENCH-SCA-021 (Transitive)
     */
    public String executeLog4j(String input) {
        // BENCH-SCA-001
        // BENCH-SCA-021
        try {
            org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(SystemDiagnosticsService.class);
            logger.error(input);
            return "Executed Log4j vulnerable path with input: " + input;
        } catch (Exception e) {
            return "Log4j Execution error: " + e.getMessage();
        }
    }

    /**
     * Jackson Databind Reachable API calls
     * BENCH-SCA-002 (Direct) & BENCH-SCA-022 (Transitive)
     */
    public String executeJackson(String jsonInput) {
        // BENCH-SCA-002
        // BENCH-SCA-022
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Object obj = mapper.readValue(jsonInput, Object.class);
            return "Executed Jackson vulnerable path. Deserialized class: " + (obj != null ? obj.getClass().getName() : "null");
        } catch (Exception e) {
            return "Jackson Execution error: " + e.getMessage();
        }
    }

    /**
     * SnakeYAML Reachable API calls
     * BENCH-SCA-003 (Direct) & BENCH-SCA-023 (Transitive)
     */
    public String executeSnakeYaml(String yamlInput) {
        // BENCH-SCA-003
        // BENCH-SCA-023
        try {
            org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml();
            Object obj = yaml.load(yamlInput);
            return "Executed SnakeYAML vulnerable path. Parsed output: " + (obj != null ? obj.toString() : "null");
        } catch (Exception e) {
            return "SnakeYAML Execution error: " + e.getMessage();
        }
    }

    /**
     * Commons Collections Reachable API calls
     * BENCH-SCA-004 (Direct) & BENCH-SCA-024 (Transitive)
     */
    public String executeCommonsCollections(String input) {
        // BENCH-SCA-004
        // BENCH-SCA-024
        try {
            org.apache.commons.collections.functors.InvokerTransformer transformer =
                    new org.apache.commons.collections.functors.InvokerTransformer("toString", new Class[0], new Object[0]);
            Object result = transformer.transform(input);
            return "Executed Commons Collections vulnerable path. Output: " + result;
        } catch (Exception e) {
            return "Commons Collections Execution error: " + e.getMessage();
        }
    }

    /**
     * Spring Core Reachable API calls
     * BENCH-SCA-005 (Direct) & BENCH-SCA-025 (Transitive)
     */
    public String executeSpringCore(String input) {
        // BENCH-SCA-005
        // BENCH-SCA-025
        try {
            Class<?> clazz = org.springframework.beans.BeanUtils.findPrimaryConstructor(String.class).getDeclaringClass();
            return "Executed Spring Core vulnerable path. Class resolved: " + clazz.getName() + " with input: " + input;
        } catch (Exception e) {
            return "Spring Core Execution error: " + e.getMessage();
        }
    }

    /**
     * Apache Commons Text Reachable API calls
     * BENCH-SCA-006 (Direct) & BENCH-SCA-026 (Transitive)
     */
    public String executeCommonsText(String input) {
        // BENCH-SCA-006
        // BENCH-SCA-026
        try {
            org.apache.commons.text.StringSubstitutor substitutor = org.apache.commons.text.StringSubstitutor.createInterpolator();
            String result = substitutor.replace(input);
            return "Executed Commons Text vulnerable path. Output: " + result;
        } catch (Exception e) {
            return "Commons Text Execution error: " + e.getMessage();
        }
    }

    /**
     * Apache HttpClient Reachable API calls
     * BENCH-SCA-007 (Direct) & BENCH-SCA-027 (Transitive)
     */
    public String executeHttpClient(String url) {
        // BENCH-SCA-007
        // BENCH-SCA-027
        try {
            org.apache.http.client.methods.HttpGet request = new org.apache.http.client.methods.HttpGet(url);
            return "Executed HttpClient vulnerable path. Request URI: " + request.getURI().toString();
        } catch (Exception e) {
            return "HttpClient Execution error: " + e.getMessage();
        }
    }

    /**
     * Bouncy Castle Reachable API calls
     * BENCH-SCA-008 (Direct) & BENCH-SCA-028 (Transitive)
     */
    public String executeBouncyCastle(String input) {
        // BENCH-SCA-008
        // BENCH-SCA-028
        try {
            org.bouncycastle.jce.provider.BouncyCastleProvider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            Security.addProvider(provider);
            return "Executed Bouncy Castle vulnerable path. Registered Provider: " + provider.getName() + " with input: " + input;
        } catch (Exception e) {
            return "Bouncy Castle Execution error: " + e.getMessage();
        }
    }

    /**
     * Hibernate Validator Reachable API calls
     * BENCH-SCA-009 (Direct) & BENCH-SCA-029 (Transitive)
     */
    public String executeHibernateValidator(String input) {
        // BENCH-SCA-009
        // BENCH-SCA-029
        try {
            jakarta.validation.Validator validator = jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();
            return "Executed Hibernate Validator vulnerable path. Validator instance: " + validator.getClass().getName() + " with input: " + input;
        } catch (Exception e) {
            return "Hibernate Validator Execution error: " + e.getMessage();
        }
    }

    /**
     * Guava Reachable API calls
     * BENCH-SCA-010 (Direct) & BENCH-SCA-030 (Transitive)
     */
    public String executeGuava(String input) {
        // BENCH-SCA-010
        // BENCH-SCA-030
        try {
            File tempDir = com.google.common.io.Files.createTempDir();
            String path = tempDir.getAbsolutePath();
            // Clean up to prevent temp dir cluttering
            tempDir.delete();
            return "Executed Guava vulnerable path. Created temporary directory: " + path + " with input: " + input;
        } catch (Exception e) {
            return "Guava Execution error: " + e.getMessage();
        }
    }

    /* ============================================================
       UNREACHABLE CODE PATH FIXTURES
       Log4j, Jackson, SnakeYAML, Commons Collections, Spring Core,
       Commons Text, HttpClient, Bouncy Castle, Hibernate Validator, Guava
       Covers BENCH-SCA-011 to 020 (Direct) & BENCH-SCA-031 to 040 (Transitive)
       ============================================================ */

    @SuppressWarnings("unused")
    private void unreachableFixtures() {
        // BENCH-SCA-011
        // BENCH-SCA-031
        org.apache.logging.log4j.LogManager.getLogger("unreachable");

        // BENCH-SCA-012
        // BENCH-SCA-032
        new com.fasterxml.jackson.databind.ObjectMapper();

        // BENCH-SCA-013
        // BENCH-SCA-033
        new org.yaml.snakeyaml.Yaml();

        // BENCH-SCA-014
        // BENCH-SCA-034
        new org.apache.commons.collections.functors.InvokerTransformer("toString", new Class[0], new Object[0]);

        // BENCH-SCA-015
        // BENCH-SCA-035
        org.springframework.beans.BeanUtils.instantiateClass(String.class);

        // BENCH-SCA-016
        // BENCH-SCA-036
        org.apache.commons.text.StringSubstitutor.createInterpolator();

        // BENCH-SCA-017
        // BENCH-SCA-037
        new org.apache.http.client.methods.HttpGet("http://unreachable.local");

        // BENCH-SCA-018
        // BENCH-SCA-038
        new org.bouncycastle.jce.provider.BouncyCastleProvider();

        // BENCH-SCA-019
        // BENCH-SCA-039
        jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();

        // BENCH-SCA-020
        // BENCH-SCA-040
        com.google.common.io.Files.fileTraverser();
    }
}
