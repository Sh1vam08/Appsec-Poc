package com.shopsphere.cart;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for DAST Cross-Site Request Forgery (CSRF) benchmark scenarios.
 * Covers BENCH-DAST-005 and BENCH-DAST-006.
 */
@RestController

public class ShoppingCartController {

    private final ShoppingCartService service;
    private static final String CSRF_TOKEN = "csrf-token-12345";

    public ShoppingCartController(ShoppingCartService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-005: CSRF (Vulnerable Variant)
     * Maps to: POST /api/dast/vulnerable/csrf
     */
    @PostMapping("/api/v1/cart/items")
    public org.springframework.web.servlet.view.RedirectView updateEmailVulnerable(@RequestParam String email, jakarta.servlet.http.HttpServletRequest request) {
        // BENCH-DAST-005
        jakarta.servlet.http.HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("USER") == null) {
            return new org.springframework.web.servlet.view.RedirectView("/?error=unauthorized");
        }
        service.updateEmail(email);
        return new org.springframework.web.servlet.view.RedirectView("/?cartAdded=true");
    }

    /**
     * BENCH-DAST-006: CSRF (Safe Variant)
     * Maps to: POST /api/dast/safe/csrf
     */
    @PostMapping("/api/v1/cart/items/secure")
    public ResponseEntity<String> updateEmailSafe(
            @RequestParam String email,
            @RequestHeader(value = "X-CSRF-TOKEN", required = false) String token,
            jakarta.servlet.http.HttpServletRequest request) {
        // BENCH-DAST-006
        jakarta.servlet.http.HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("USER") == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized: Active session required.");
        }
        if (token == null || !token.equals(CSRF_TOKEN)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("CSRF validation failed: Missing or invalid X-CSRF-TOKEN header.");
        }
        service.updateEmail(email);
        return ResponseEntity.ok("Email updated to: " + service.getEmail() + " (Safe CSRF endpoint)");
    }
}
