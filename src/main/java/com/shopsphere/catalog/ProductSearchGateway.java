package com.shopsphere.catalog;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

/**
 * Controller for DAST SQL Injection benchmark scenarios.
 * Covers BENCH-DAST-001 and BENCH-DAST-002.
 */
@RestController

public class ProductSearchGateway {

    private final ProductSearchGatewayService service;

    public ProductSearchGateway(ProductSearchGatewayService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-001: SQL Injection (Vulnerable Variant)
     * Maps to: POST /api/dast/vulnerable/sqli
     */
    @PostMapping("/api/v1/catalog/query")
    public List<Object[]> getVulnerable(@RequestParam String username) {
        // BENCH-DAST-001
        return service.queryVulnerable(username);
    }

    /**
     * BENCH-DAST-002: SQL Injection (Safe Variant)
     * Maps to: POST /api/dast/safe/sqli
     */
    @PostMapping("/api/v1/catalog/query/secure")
    public List<Object[]> getSafe(@RequestParam String username) {
        // BENCH-DAST-002
        return service.querySafe(username);
    }
}
