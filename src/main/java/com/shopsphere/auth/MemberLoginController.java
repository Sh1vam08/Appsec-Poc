package com.shopsphere.controller.dast.auth;

import com.shopsphere.service.dast.auth.MemberLoginService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for DAST Authentication Weakness benchmark scenarios.
 * Covers BENCH-DAST-015 and BENCH-DAST-016.
 */
@RestController

public class MemberLoginController {

    private final MemberLoginService service;

    public MemberLoginController(MemberLoginService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-015: Authentication Weakness (Vulnerable Variant)
     * Maps to: POST /api/dast/vulnerable/auth
     */
    @PostMapping("/api/v1/auth/member-login")
    public ResponseEntity<String> loginVulnerable(@RequestParam String username, @RequestParam String password) {
        // BENCH-DAST-015
        boolean authenticated = service.authenticateVulnerable(username, password);
        if (authenticated) {
            return ResponseEntity.ok("Login successful (Vulnerable Endpoint)");
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
    }

    /**
     * BENCH-DAST-016: Authentication Weakness (Safe Variant)
     * Maps to: POST /api/dast/safe/auth
     */
    @PostMapping("/api/v1/auth/member-login/secure")
    public ResponseEntity<String> loginSafe(@RequestParam String username, @RequestParam String password) {
        // BENCH-DAST-016
        boolean authenticated = service.authenticateSafe(username, password);
        if (authenticated) {
            return ResponseEntity.ok("Login successful (Safe Endpoint)");
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
    }
}
