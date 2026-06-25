package com.shopsphere.payment;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Hardcoded Credentials benchmark scenarios.
 * Covers BENCH-SAST-073 through BENCH-SAST-076.
 */
@RestController

public class PaymentGatewayConfigController {

    private final PaymentGatewayConfigService hardcodedCredsService;

    public PaymentGatewayConfigController(PaymentGatewayConfigService hardcodedCredsService) {
        this.hardcodedCredsService = hardcodedCredsService;
    }

    /**
     * BENCH-SAST-073: Hardcoded Credentials (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/hardcoded-creds
     */
    @GetMapping("/api/v1/payments/gateway/config")
    public String getVulnerable() {
        // BENCH-SAST-073
        boolean success = hardcodedCredsService.testConnectionVulnerable();
        return success ? "Connection Success (Vulnerable)" : "Connection Failed (Vulnerable path executed)";
    }

    /**
     * BENCH-SAST-074: Hardcoded Credentials (Safe Variant)
     * Maps to: GET /api/safe/hardcoded-creds
     */
    @GetMapping("/api/v1/payments/gateway/config/secure")
    public String getSafe() {
        // BENCH-SAST-074
        boolean success = hardcodedCredsService.testConnectionSafe();
        return success ? "Connection Success (Safe)" : "Connection Failed (Safe path executed)";
    }

    /**
     * BENCH-SAST-076: Hardcoded Credentials (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/hardcoded-creds
     */
    @GetMapping("/api/v1/payments/gateway/config/vault")
    public String getFrameworkProtected() {
        // BENCH-SAST-076
        boolean success = hardcodedCredsService.testConnectionFrameworkProtected();
        return success ? "Connection Success (Framework-Protected)" : "Connection Failed (Framework-Protected path executed)";
    }
}
