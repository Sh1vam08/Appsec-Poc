package com.shopsphere.controller.sast.auth;

import com.shopsphere.service.sast.auth.UserAuthenticationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Broken Authentication benchmark scenarios.
 * Covers BENCH-SAST-061 through BENCH-SAST-064.
 */
@RestController

public class UserAuthenticationController {

    private final UserAuthenticationService brokenAuthService;

    public UserAuthenticationController(UserAuthenticationService brokenAuthService) {
        this.brokenAuthService = brokenAuthService;
    }

    /**
     * BENCH-SAST-061: Broken Authentication (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/broken-auth
     */
    @GetMapping("/api/v1/auth/customer-login")
    public String getVulnerable(@RequestParam String username, @RequestParam String password) {
        boolean success = brokenAuthService.authenticateVulnerable(username, password);
        return success ? "Auth Success (Vulnerable)" : "Auth Failed";
    }

    /**
     * BENCH-SAST-062: Broken Authentication (Safe Variant)
     * Maps to: GET /api/safe/broken-auth
     */
    @GetMapping("/api/v1/auth/customer-login/secure")
    public String getSafe(@RequestParam String username, @RequestParam String password) {
        boolean success = brokenAuthService.authenticateSafe(username, password);
        return success ? "Auth Success (Safe)" : "Auth Failed";
    }

    /**
     * BENCH-SAST-064: Broken Authentication (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/broken-auth
     */
    @GetMapping("/api/v1/auth/customer-login/oauth")
    public String getFrameworkProtected(@RequestParam String username, @RequestParam String password) {
        boolean success = brokenAuthService.authenticateFrameworkProtected(username, password);
        return success ? "Auth Success (Framework-Protected)" : "Auth Failed";
    }
}
