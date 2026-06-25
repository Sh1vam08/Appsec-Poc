package com.shopsphere.auth;

import com.shopsphere.model.entity.User;
import com.shopsphere.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

/**
 * Service for Broken Authentication benchmark scenarios.
 * Covers BENCH-SAST-061 through BENCH-SAST-064.
 */
@Service
public class UserAuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public UserAuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    /**
     * BENCH-SAST-061: Broken Authentication (Vulnerable Variant)
     * Performs direct string comparison against database passwords without utilizing hashing.
     */
    public boolean authenticateVulnerable(String username, String password) {
        // BENCH-SAST-061
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Sink: raw plain-text password comparison
            return password.equals(user.getPassword());
        }
        return false;
    }

    /**
     * BENCH-SAST-062: Broken Authentication (Safe Variant)
     * Uses standard PasswordEncoder hash comparison to secure authentication.
     */
    public boolean authenticateSafe(String username, String password) {
        // BENCH-SAST-062
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Safe: Uses BCrypt validation matching
            return passwordEncoder.matches(password, user.getPassword());
        }
        return false;
    }

    /**
     * BENCH-SAST-063: Broken Authentication (Unreachable Variant)
     * Unreachable helper executing vulnerable string comparison checks.
     */
    @SuppressWarnings("unused")
    private boolean authenticateUnreachable(String username, String password) {
        // BENCH-SAST-063
        Optional<User> userOpt = userRepository.findByUsername(username);
        return userOpt.map(user -> password.equals(user.getPassword())).orElse(false);
    }

    /**
     * BENCH-SAST-064: Broken Authentication (Framework-Protected Variant)
     * Delegates authentication completely to Spring Security's AuthenticationManager,
     * leveraging standard container authorization context.
     */
    public boolean authenticateFrameworkProtected(String username, String password) {
        // BENCH-SAST-064
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
            );
            return auth.isAuthenticated();
        } catch (Exception e) {
            return false;
        }
    }
}
