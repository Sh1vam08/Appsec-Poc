package com.shopsphere.catalog;

import com.shopsphere.model.entity.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

/**
 * Controller for SQL Injection (SQLi) benchmark scenarios.
 * Covers BENCH-SAST-001 through BENCH-SAST-004.
 */
@RestController

public class ProductCatalogController {

    private final ProductCatalogService sqlInjectionService;

    public ProductCatalogController(ProductCatalogService sqlInjectionService) {
        this.sqlInjectionService = sqlInjectionService;
    }

    /**
     * BENCH-SAST-001: SQL Injection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/sqli
     */
    @GetMapping("/api/v1/products/search")
    public List<User> getVulnerable(@RequestParam String username) {
        return sqlInjectionService.searchVulnerable(username);
    }

    /**
     * BENCH-SAST-002: SQL Injection (Safe Variant)
     * Maps to: GET /api/safe/sqli
     */
    @GetMapping("/api/v1/products/search/secure")
    public List<User> getSafe(@RequestParam String username) {
        return sqlInjectionService.searchSafe(username);
    }

    /**
     * BENCH-SAST-004: SQL Injection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/sqli
     */
    @GetMapping("/api/v1/products/search/jpa")
    public List<User> getFrameworkProtected(@RequestParam String username) {
        return sqlInjectionService.searchFrameworkProtected(username);
    }
}
