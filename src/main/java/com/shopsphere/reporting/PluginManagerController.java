package com.shopsphere.reporting;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Unsafe Reflection benchmark scenarios.
 * Covers BENCH-SAST-057 through BENCH-SAST-060.
 */
@RestController

public class PluginManagerController {

    private final PluginManagerService unsafeReflectionService;

    public PluginManagerController(PluginManagerService unsafeReflectionService) {
        this.unsafeReflectionService = unsafeReflectionService;
    }

    /**
     * BENCH-SAST-057: Unsafe Reflection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/reflection
     */
    @GetMapping("/api/v1/system/plugins/load")
    public String getVulnerable(@RequestParam String className) {
        Object obj = unsafeReflectionService.instantiateVulnerable(className);
        return obj != null ? "Instantiated: " + obj.getClass().getName() : "null";
    }

    /**
     * BENCH-SAST-058: Unsafe Reflection (Safe Variant)
     * Maps to: GET /api/safe/reflection
     */
    @GetMapping("/api/v1/system/plugins/load/secure")
    public String getSafe(@RequestParam String className) {
        Object obj = unsafeReflectionService.instantiateSafe(className);
        return obj != null ? "Instantiated safely: " + obj.getClass().getName() : "null";
    }

    /**
     * BENCH-SAST-060: Unsafe Reflection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/reflection
     */
    @GetMapping("/api/v1/system/plugins/load/di")
    public String getFrameworkProtected(@RequestParam String key) {
        Object obj = unsafeReflectionService.instantiateFrameworkProtected(key);
        return obj != null ? "Instantiated via registry: " + obj.getClass().getName() : "null";
    }
}
