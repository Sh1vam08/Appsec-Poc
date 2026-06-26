package com.shopsphere.common;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Controller for Denial of Service (DoS) benchmark scenarios.
 * BENCH-SAST-108: Regular Expression Denial of Service (ReDoS)
 */
@RestController
@RequestMapping("/api/v1/validation")
public class RegexValidationController {

    // BENCH-SAST-108
    // Vulnerable: Catastrophic backtracking regex.
    // E.g., matching a long string of 'a's ending in 'X': aaaaaaaaaaaaaaaaaaaaaaaaaaaaaX
    private static final Pattern VULNERABLE_REGEX = Pattern.compile("^(([a-zA-Z0-9])+)+$");

    @PostMapping("/promo")
    public ResponseEntity<String> validatePromoCode(@RequestParam String code) {
        
        Matcher matcher = VULNERABLE_REGEX.matcher(code);
        
        // This will block the thread if catastrophic backtracking occurs
        if (matcher.matches()) {
            return ResponseEntity.ok("Promo code format is valid.");
        } else {
            return ResponseEntity.badRequest().body("Invalid promo code format.");
        }
    }
}
