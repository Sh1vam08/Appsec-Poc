package com.shopsphere.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Date;
import java.util.Map;

/**
 * Controller for JWT benchmark scenarios.
 * BENCH-SAST-095: Weak JWT Signature (Vulnerable Variant)
 * BENCH-SAST-096: "none" Algorithm Acceptance (Vulnerable Variant)
 */
@RestController
@RequestMapping("/api/v1/auth/jwt")
public class JwtAuthenticationController {

    private static final String WEAK_SECRET = "secret"; // Vulnerable: Easily crackable

    @SuppressWarnings("deprecation")
    @PostMapping("/login")
    public ResponseEntity<String> generateToken(@RequestParam String username) {
        String token = Jwts.builder()
                .setSubject(username)
                .claim("role", "USER")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.HS256, WEAK_SECRET.getBytes()) // BENCH-SAST-095
                .compact();
        return ResponseEntity.ok(token);
    }

    /**
     * BENCH-SAST-096: JWT "none" Algorithm Acceptance (Vulnerable Variant)
     * Manually parses the JWT without enforcing signature validation,
     * allowing attackers to simply strip the signature or use "alg":"none".
     */
    @GetMapping("/verify/vulnerable")
    public ResponseEntity<String> verifyVulnerable(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Missing token");
        }
        
        String token = authHeader.substring(7);
        try {
            // Vulnerable Sink: parsing without verifying signature correctly (or accepting unsigned claims)
            // Note: Modern jjwt versions throw exception on parse() without key, so we use parseClaimsJwt for unsigned,
            // or we decode base64 manually to represent the vulnerability.
            
            // Simulating a flawed implementation that parses payload directly without signature check
            String[] parts = token.split("\\.");
            if (parts.length < 2) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token");
            
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            return ResponseEntity.ok("Token parsed blindly (Vulnerable): " + payload);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }
}
