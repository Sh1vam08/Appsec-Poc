package com.shopsphere.review;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller for DOM-based XSS benchmark scenarios.
 * Covers BENCH-SAST-037 through BENCH-SAST-040.
 */
@Controller

public class ProfileDetailsController {

    private final ProfileDetailsService domXssService;

    public ProfileDetailsController(ProfileDetailsService domXssService) {
        this.domXssService = domXssService;
    }

    /**
     * BENCH-SAST-037: DOM-based XSS (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/dom-xss
     */
    @GetMapping("/profile/details")
    public String getVulnerable() {
        return domXssService.renderVulnerable();
    }

    /**
     * BENCH-SAST-038: DOM-based XSS (Safe Variant)
     * Maps to: GET /api/safe/dom-xss
     */
    @GetMapping("/profile/details/secure")
    public String getSafe() {
        return domXssService.renderSafe();
    }

    /**
     * BENCH-SAST-040: DOM-based XSS (Framework-Protected Variant)
     * Renders template configured with standard DOM text elements, preventing scripting parsing.
     * Maps to: GET /api/framework-protected/dom-xss
     */
    @GetMapping("/profile/details/angular")
    public String getFrameworkProtected() {
        // BENCH-SAST-040
        return domXssService.renderSafe();
    }
}
