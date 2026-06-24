package com.shopsphere.controller.dast.redirect;

import com.shopsphere.service.dast.redirect.OAuthRedirectService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

/**
 * Controller for DAST Open Redirect benchmark scenarios.
 * Covers BENCH-DAST-009 and BENCH-DAST-010.
 */
@RestController

public class OAuthRedirectController {

    private final OAuthRedirectService service;

    public OAuthRedirectController(OAuthRedirectService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-009: Open Redirect (Vulnerable Variant)
     * Maps to: GET /api/dast/vulnerable/redirect
     */
    @GetMapping("/api/v1/auth/oauth/redirect")
    public void redirectVulnerable(@RequestParam String url, HttpServletResponse response) throws IOException {
        // BENCH-DAST-009
        service.logRedirect(url);
        response.sendRedirect(url);
    }

    /**
     * BENCH-DAST-010: Open Redirect (Safe Variant)
     * Maps to: GET /api/dast/safe/redirect
     */
    @GetMapping("/api/v1/auth/oauth/redirect/secure")
    public void redirectSafe(@RequestParam String url, HttpServletResponse response) throws IOException {
        // BENCH-DAST-010
        service.logRedirect(url);
        if (service.isValidRedirect(url)) {
            response.sendRedirect(url);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Open Redirect Attempt Blocked.");
        }
    }
}
