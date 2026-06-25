package com.shopsphere.auth;

import com.shopsphere.model.entity.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

/**
 * Service for DAST Authentication Weakness benchmark scenarios.
 * Covers BENCH-DAST-015 and BENCH-DAST-016.
 */
@Service
public class MemberLoginService {

    private final MemberLoginRepository repository;
    private final PasswordEncoder passwordEncoder;

    public MemberLoginService(MemberLoginRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * BENCH-DAST-015: Authentication Weakness (Vulnerable Variant)
     * Sink: allows logging in with default config credentials admin/admin directly.
     */
    public boolean authenticateVulnerable(String username, String password) {
        // BENCH-DAST-015
        if ("admin".equals(username) && "admin".equals(password)) {
            // Vulnerable sink: default admin accounts hardcoded
            return true;
        }
        Optional<User> userOpt = repository.findByUsername(username);
        return userOpt.map(user -> passwordEncoder.matches(password, user.getPassword())).orElse(false);
    }

    /**
     * BENCH-DAST-016: Authentication Weakness (Safe Variant)
     * Enforces database validation and does not permit static defaults.
     */
    public boolean authenticateSafe(String username, String password) {
        // BENCH-DAST-016
        // Safe: Disallow hardcoded defaults completely and validate hash
        if ("admin".equals(username) && "admin".equals(password)) {
            return false;
        }
        Optional<User> userOpt = repository.findByUsername(username);
        return userOpt.map(user -> passwordEncoder.matches(password, user.getPassword())).orElse(false);
    }
}
