package com.shopsphere.catalog;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for XPath Injection benchmark scenarios.
 * Covers BENCH-SAST-017 through BENCH-SAST-020.
 */
@RestController

public class CatalogImportController {

    private final CatalogImportService xpathInjectionService;

    public CatalogImportController(CatalogImportService xpathInjectionService) {
        this.xpathInjectionService = xpathInjectionService;
    }

    /**
     * BENCH-SAST-017: XPath Injection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/xpath
     */
    @GetMapping("/api/v1/catalog/import")
    public String getVulnerable(@RequestParam String username) {
        return xpathInjectionService.searchVulnerable(username);
    }

    /**
     * BENCH-SAST-018: XPath Injection (Safe Variant)
     * Maps to: GET /api/safe/xpath
     */
    @GetMapping("/api/v1/catalog/import/secure")
    public String getSafe(@RequestParam String username) {
        return xpathInjectionService.searchSafe(username);
    }

    /**
     * BENCH-SAST-020: XPath Injection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/xpath
     */
    @GetMapping("/api/v1/catalog/import/dom")
    public String getFrameworkProtected(@RequestParam String username) {
        return xpathInjectionService.searchFrameworkProtected(username);
    }
}
