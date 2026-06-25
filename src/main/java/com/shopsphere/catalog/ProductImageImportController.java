package com.shopsphere.catalog;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Server-Side Request Forgery (SSRF) benchmark scenarios.
 * Covers BENCH-SAST-041 through BENCH-SAST-044.
 */
@RestController

public class ProductImageImportController {

    private final ProductImageImportService ssrfService;

    public ProductImageImportController(ProductImageImportService ssrfService) {
        this.ssrfService = ssrfService;
    }

    /**
     * BENCH-SAST-041: SSRF (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/ssrf
     */
    @GetMapping("/api/v1/products/image-import")
    public String getVulnerable(@RequestParam String url) {
        return ssrfService.requestVulnerable(url);
    }

    /**
     * BENCH-SAST-042: SSRF (Safe Variant)
     * Maps to: GET /api/safe/ssrf
     */
    @GetMapping("/api/v1/products/image-import/secure")
    public String getSafe(@RequestParam String url) {
        return ssrfService.requestSafe(url);
    }

    /**
     * BENCH-SAST-044: SSRF (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/ssrf
     */
    @GetMapping("/api/v1/products/image-import/fixed")
    public String getFrameworkProtected(@RequestParam String url) {
        return ssrfService.requestFrameworkProtected(url);
    }
}
