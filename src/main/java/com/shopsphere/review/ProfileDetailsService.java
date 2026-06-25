package com.shopsphere.review;

import org.springframework.stereotype.Service;

/**
 * Service for DOM-based XSS benchmark scenarios.
 * Since DOM-based XSS executes client-side, this service manages template selection and unreachable hooks.
 */
@Service
public class ProfileDetailsService {

    public String renderVulnerable() {
        return "xss_dom_vulnerable";
    }

    public String renderSafe() {
        return "xss_dom_safe";
    }

    /**
     * BENCH-SAST-039: DOM-based XSS (Unreachable Variant)
     * This private helper is never reached.
     */
    @SuppressWarnings("unused")
    private String renderUnreachable() {
        // BENCH-SAST-039
        return "xss_dom_vulnerable";
    }
}
