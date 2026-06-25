package com.shopsphere.common;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for DAST SSRF benchmark scenarios.
 * Covers BENCH-DAST-007 and BENCH-DAST-008.
 */
@RestController

public class VendorWebhookController {

    private final VendorWebhookService service;

    public VendorWebhookController(VendorWebhookService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-007: SSRF (Vulnerable Variant)
     * Maps to: POST /api/dast/vulnerable/ssrf
     */
    @PostMapping("/api/v1/vendors/webhooks")
    public String postVulnerable(@RequestParam String url) {
        // BENCH-DAST-007
        return service.fetchUrlVulnerable(url);
    }

    /**
     * BENCH-DAST-008: SSRF (Safe Variant)
     * Maps to: POST /api/dast/safe/ssrf
     */
    @PostMapping("/api/v1/vendors/webhooks/secure")
    public String postSafe(@RequestParam String url) {
        // BENCH-DAST-008
        return service.fetchUrlSafe(url);
    }
}
