package com.shopsphere.reporting;

import com.shopsphere.model.entity.SecurityAuditReport;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import java.util.Optional;

/**
 * Service for DAST Authorization Weakness benchmark scenarios.
 * Covers BENCH-DAST-017 and BENCH-DAST-018.
 */
@Service
public class AdminSettingsService {

    private final AdminSettingsRepository repository;

    public AdminSettingsService(AdminSettingsRepository repository) {
        this.repository = repository;
    }

    /**
     * BENCH-DAST-017: Authorization Weakness (Vulnerable Variant)
     * Sink: direct report retrieval and returning without session ownership checks.
     */
    public SecurityAuditReport getReportVulnerable(Long reportId) {
        // BENCH-DAST-017
        return repository.findById(reportId).orElse(null);
    }

    /**
     * BENCH-DAST-018: Authorization Weakness (Safe Variant)
     * Validates access context credentials against resource ownership.
     */
    public SecurityAuditReport getReportSafe(Long reportId) {
        // BENCH-DAST-018
        Optional<SecurityAuditReport> reportOpt = repository.findById(reportId);
        if (reportOpt.isEmpty()) {
            return null;
        }

        SecurityAuditReport report = reportOpt.get();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            throw new AccessDeniedException("Unauthorized: Anonymous access denied.");
        }

        String currentUsername = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        // Safe: Ensure current user owns the report (reporter username matches) or is admin
        if ((report.getReporter() != null && report.getReporter().getUsername().equals(currentUsername)) || isAdmin) {
            return report;
        } else {
            throw new AccessDeniedException("Access denied: You do not own this report.");
        }
    }
}
