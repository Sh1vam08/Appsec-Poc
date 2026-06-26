package com.shopsphere.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.MessageDigest;
import java.util.Random;

/**
 * Controller for Cryptography benchmark scenarios.
 * BENCH-SAST-109: Insecure Randomness (CWE-330)
 * BENCH-SAST-110: Broken or Risky Cryptographic Algorithm (CWE-327)
 */
@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    /**
     * BENCH-SAST-109: Insecure Randomness
     * Generates a password reset token using java.util.Random instead of SecureRandom.
     */
    @GetMapping("/reset-token")
    public ResponseEntity<String> generateResetToken() {
        // Vulnerable: Predictable PRNG
        Random random = new Random();
        long token = random.nextLong();
        return ResponseEntity.ok("Reset Token: " + Long.toHexString(token));
    }

    /**
     * BENCH-SAST-110: Broken Cryptography
     * Hashes a password using the obsolete and broken MD5 algorithm.
     */
    @PostMapping("/hash")
    public ResponseEntity<String> hashPassword(@RequestParam String password) {
        try {
            // Vulnerable: MD5 is not collision-resistant and too fast for passwords
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(password.getBytes());
            byte[] digest = md.digest();
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b));
            }
            return ResponseEntity.ok("Hash: " + hexString.toString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}
