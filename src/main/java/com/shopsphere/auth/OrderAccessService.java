package com.shopsphere.service.sast.auth;

import com.shopsphere.model.entity.User;
import com.shopsphere.repository.UserRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import java.util.Optional;

/**
 * Service for Broken Authorization (Access Control) benchmark scenarios.
 * Covers BENCH-SAST-065 through BENCH-SAST-068.
 */
@Service
public class OrderAccessService {

    private final UserRepository userRepository;

    public OrderAccessService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * BENCH-SAST-065: Broken Authorization (Vulnerable Variant)
     * Direct Object Reference: loads other users' records directly without ownership validation.
     */
    public User getUserDataVulnerable(Long userId) {
        // BENCH-SAST-065
        // Sink: direct database query and returning user entity without authorization checks
        return userRepository.findById(userId).orElse(null);
    }

    /**
     * BENCH-SAST-066: Broken Authorization (Safe Variant)
     * Performs manual authentication context checks to ensure the requesting user owns the resource
     * or holds administrative privileges.
     */
    public User getUserDataSafe(Long userId) {
        // BENCH-SAST-066
        Optional<User> targetUserOpt = userRepository.findById(userId);
        if (targetUserOpt.isEmpty()) {
            return null;
        }

        User targetUser = targetUserOpt.get();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null) {
            throw new AccessDeniedException("Anonymous users cannot access records.");
        }

        String currentUsername = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

        // Validate resource ownership or admin role authorization
        if (targetUser.getUsername().equals(currentUsername) || isAdmin) {
            return targetUser;
        } else {
            throw new AccessDeniedException("Access denied: You do not own this resource.");
        }
    }

    /**
     * BENCH-SAST-067: Broken Authorization (Unreachable Variant)
     * Unreachable helper fetching user entity without authorization checks.
     */
    @SuppressWarnings("unused")
    private User getUserDataUnreachable(Long userId) {
        // BENCH-SAST-067
        return userRepository.findById(userId).orElse(null);
    }

    /**
     * BENCH-SAST-068: Broken Authorization (Framework-Protected Variant)
     * Secures method access using Spring Security's SpEL method security annotations.
     * Evaluates ownership or role criteria natively before executing the method body.
     */
    @PreAuthorize("#username == authentication.name or hasRole('ADMIN')")
    public User getUserDataFrameworkProtected(String username) {
        // BENCH-SAST-068
        return userRepository.findByUsername(username).orElse(null);
    }
}
