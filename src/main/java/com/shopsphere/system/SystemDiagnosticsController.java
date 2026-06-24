package com.shopsphere.controller.sca;

import com.shopsphere.service.sca.SystemDiagnosticsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for SCA Benchmark Scenarios.
 * Exposes endpoints for executing vulnerable paths in configured libraries.
 * Covers BENCH-SCA-001 to BENCH-SCA-040.
 */
@RestController

public class SystemDiagnosticsController {

    private final SystemDiagnosticsService scaService;

    public SystemDiagnosticsController(SystemDiagnosticsService scaService) {
        this.scaService = scaService;
    }

    @GetMapping("/api/v1/system/update/check/log4j-core")
    public String executeLog4j(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeLog4j(input);
    }

    @GetMapping("/api/v1/system/update/check/jackson-databind")
    public String executeJackson(@RequestParam(defaultValue = "{}") String jsonInput) {
        return scaService.executeJackson(jsonInput);
    }

    @GetMapping("/api/v1/system/update/check/snakeyaml")
    public String executeSnakeYaml(@RequestParam(defaultValue = "test: value") String yamlInput) {
        return scaService.executeSnakeYaml(yamlInput);
    }

    @GetMapping("/api/v1/system/update/check/commons-collections")
    public String executeCommonsCollections(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeCommonsCollections(input);
    }

    @GetMapping("/api/v1/system/update/check/spring-core")
    public String executeSpringCore(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeSpringCore(input);
    }

    @GetMapping("/api/v1/system/update/check/commons-text")
    public String executeCommonsText(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeCommonsText(input);
    }

    @GetMapping("/api/v1/system/update/check/httpclient")
    public String executeHttpClient(@RequestParam(defaultValue = "http://localhost:8080/actuator/health") String url) {
        return scaService.executeHttpClient(url);
    }

    @GetMapping("/api/v1/system/update/check/bcprov-jdk15on")
    public String executeBouncyCastle(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeBouncyCastle(input);
    }

    @GetMapping("/api/v1/system/update/check/hibernate-validator")
    public String executeHibernateValidator(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeHibernateValidator(input);
    }

    @GetMapping("/api/v1/system/update/check/guava")
    public String executeGuava(@RequestParam(defaultValue = "test") String input) {
        return scaService.executeGuava(input);
    }

    @GetMapping("/api/v1/system/update/check")
    public String getVulnerable() {
        return "vulnerable";
    }

    @GetMapping("/api/v1/system/update/check/secure")
    public String getSafe() {
        return "secure";
    }

    @GetMapping("/api/v1/framework-protected/sca")
    public String getFrameworkProtected() {
        return "framework-protected";
    }
}
