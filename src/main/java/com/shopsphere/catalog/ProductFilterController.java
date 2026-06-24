package com.shopsphere.controller.sast.injection;

import com.shopsphere.service.sast.injection.ProductFilterService;
import org.bson.Document;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

/**
 * Controller for NoSQL Injection (NoSQLi) benchmark scenarios.
 * Covers BENCH-SAST-005 through BENCH-SAST-008.
 */
@RestController

public class ProductFilterController {

    private final ProductFilterService noProductCatalogService;

    public ProductFilterController(ProductFilterService noProductCatalogService) {
        this.noProductCatalogService = noProductCatalogService;
    }

    /**
     * BENCH-SAST-005: NoSQL Injection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/nosqli
     */
    @GetMapping("/api/v1/products/filter")
    public List<Document> getVulnerable(@RequestParam String username) {
        return noProductCatalogService.searchVulnerable(username);
    }

    /**
     * BENCH-SAST-006: NoSQL Injection (Safe Variant)
     * Maps to: GET /api/safe/nosqli
     */
    @GetMapping("/api/v1/products/filter/secure")
    public List<Document> getSafe(@RequestParam String username) {
        return noProductCatalogService.searchSafe(username);
    }

    /**
     * BENCH-SAST-008: NoSQL Injection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/nosqli
     */
    @GetMapping("/api/v1/products/filter/jpa")
    public List<Document> getFrameworkProtected(@RequestParam String username) {
        return noProductCatalogService.searchFrameworkProtected(username);
    }
}
