package com.shopsphere.controller.sast.crypto;

import com.shopsphere.service.sast.crypto.DataEncryptionService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Weak Cryptography benchmark scenarios.
 * Covers BENCH-SAST-069 through BENCH-SAST-072.
 */
@RestController

public class DataEncryptionController {

    private final DataEncryptionService weakCryptoService;

    public DataEncryptionController(DataEncryptionService weakCryptoService) {
        this.weakCryptoService = weakCryptoService;
    }

    /**
     * BENCH-SAST-069: Weak Cryptography (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/weak-crypto
     */
    @GetMapping("/api/v1/payments/encrypt")
    public String getVulnerable(@RequestParam String text) {
        // BENCH-SAST-069
        return weakCryptoService.encryptVulnerable(text);
    }

    /**
     * BENCH-SAST-070: Weak Cryptography (Safe Variant)
     * Maps to: GET /api/safe/weak-crypto
     */
    @GetMapping("/api/v1/payments/encrypt/secure")
    public String getSafe(@RequestParam String text) {
        // BENCH-SAST-070
        return weakCryptoService.encryptSafe(text);
    }

    /**
     * BENCH-SAST-072: Weak Cryptography (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/weak-crypto
     */
    @GetMapping("/api/v1/payments/encrypt/standard")
    public String getFrameworkProtected(@RequestParam String text) {
        // BENCH-SAST-072
        return weakCryptoService.encryptFrameworkProtected(text);
    }
}
