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

    /**
     * BENCH-DAST-099: Blind SSRF
     * Maps to: POST /api/v1/vendors/webhooks/blind
     * Discards the response, forcing the DAST tool to use Out-of-Band (OAST) techniques.
     */
    @PostMapping("/api/v1/vendors/webhooks/blind")
    public String postBlind(@RequestParam String url) {
        // BENCH-DAST-099
        service.fetchUrlBlind(url);
        return "Webhook dispatched successfully.";
    }

    /**
     * BENCH-DAST-100: Cloud Metadata SSRF
     * Maps to: POST /api/v1/vendors/webhooks/metadata
     * Attempts to read AWS metadata if the attacker provides 169.254.169.254.
     */
    @PostMapping("/api/v1/vendors/webhooks/metadata")
    public String postMetadata(@RequestParam String url) {
        // BENCH-DAST-100
        return service.fetchUrlVulnerable(url);
    }
}
