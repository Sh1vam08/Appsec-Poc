package com.shopsphere.reporting;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Controller for BFLA benchmark scenarios.
 * BENCH-DAST-092: Broken Function Level Authorization (Vulnerable Variant)
 * BENCH-DAST-093: Broken Function Level Authorization (Safe Variant)
 */
@RestController
@RequestMapping("/api/v1/admin/reports")
public class AdminReportController {

    /**
     * BENCH-DAST-092: BFLA (Vulnerable Variant)
     * Maps to: DELETE /api/v1/admin/reports/vulnerable/{id}
     * Missing admin role check; any authenticated user can delete the report.
     */
    @DeleteMapping("/vulnerable/{id}")
    public ResponseEntity<String> deleteReportVulnerable(@PathVariable("id") String id, HttpServletRequest request) {
        // BENCH-DAST-092
        String currentUser = (String) request.getSession(true).getAttribute("USER");
        if (currentUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Must be logged in");
        }
        
        // Vulnerable: No role verification performed.
        return ResponseEntity.ok("Report " + id + " successfully deleted by " + currentUser);
    }

    /**
     * BENCH-DAST-093: BFLA (Safe Variant)
     * Maps to: DELETE /api/v1/admin/reports/safe/{id}
     * Verifies the user has the ADMIN role before execution.
     */
    @DeleteMapping("/safe/{id}")
    public ResponseEntity<String> deleteReportSafe(@PathVariable("id") String id, HttpServletRequest request) {
        // BENCH-DAST-093
        String currentUser = (String) request.getSession(true).getAttribute("USER");
        if (currentUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Must be logged in");
        }
        
        // Safe: Mock role verification (assuming only 'admin' has ADMIN role here)
        if (!"admin".equalsIgnoreCase(currentUser)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden: Administrator access required.");
        }
        
        return ResponseEntity.ok("Report " + id + " successfully deleted by " + currentUser);
    }
}
