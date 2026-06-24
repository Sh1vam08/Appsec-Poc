package com.shopsphere.controller.dast.authz;

import com.shopsphere.model.entity.SecurityAuditReport;
import com.shopsphere.service.dast.authz.AdminSettingsService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for DAST Authorization Weakness benchmark scenarios.
 * Covers BENCH-DAST-017 and BENCH-DAST-018.
 */
@RestController

public class AdminSettingsController {

    private final AdminSettingsService service;

    public AdminSettingsController(AdminSettingsService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-017: Authorization Weakness (Vulnerable Variant)
     * Maps to: GET /api/dast/vulnerable/authz
     */
    @GetMapping("/api/v1/admin/settings")
    public ResponseEntity<SecurityAuditReport> getVulnerable(@RequestParam Long reportId) {
        // BENCH-DAST-017
        SecurityAuditReport report = service.getReportVulnerable(reportId);
        return ResponseEntity.ok(report);
    }

    /**
     * BENCH-DAST-018: Authorization Weakness (Safe Variant)
     * Maps to: GET /api/dast/safe/authz
     */
    @GetMapping("/api/v1/admin/settings/secure")
    public ResponseEntity<Object> getSafe(@RequestParam Long reportId) {
        // BENCH-DAST-018
        try {
            SecurityAuditReport report = service.getReportSafe(reportId);
            return ResponseEntity.ok(report);
        } catch (AccessDeniedException ade) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ade.getMessage());
        }
    }
}
