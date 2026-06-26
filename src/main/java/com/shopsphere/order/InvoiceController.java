package com.shopsphere.order;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Controller for BOLA/IDOR benchmark scenarios.
 * BENCH-DAST-090: Broken Object Level Authorization (Vulnerable Variant)
 * BENCH-DAST-091: Broken Object Level Authorization (Safe Variant)
 */
@RestController
@RequestMapping("/api/v1/invoices")
public class InvoiceController {

    /**
     * BENCH-DAST-090: BOLA (Vulnerable Variant)
     * Maps to: GET /api/v1/invoices/vulnerable/{id}
     * Does not check if the requested invoice belongs to the currently authenticated user.
     */
    @GetMapping("/vulnerable/{id}")
    public ResponseEntity<String> getInvoiceVulnerable(@PathVariable("id") String id, HttpServletRequest request) {
        // BENCH-DAST-090
        String currentUser = (String) request.getSession(true).getAttribute("USER");
        if (currentUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Must be logged in");
        }
        
        // Vulnerable: Returns invoice regardless of ownership
        return ResponseEntity.ok("Invoice Details for ID " + id + " | Owner: ANY");
    }

    /**
     * BENCH-DAST-091: BOLA (Safe Variant)
     * Maps to: GET /api/v1/invoices/safe/{id}
     * Validates that the invoice ID specifically belongs to the currently authenticated user.
     */
    @GetMapping("/safe/{id}")
    public ResponseEntity<String> getInvoiceSafe(@PathVariable("id") String id, HttpServletRequest request) {
        // BENCH-DAST-091
        String currentUser = (String) request.getSession(true).getAttribute("USER");
        if (currentUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Must be logged in");
        }

        // Mock ownership check: Assuming invoice IDs start with the username for this simple mock
        if (!id.startsWith(currentUser)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied: You do not own this invoice.");
        }
        
        return ResponseEntity.ok("Invoice Details for ID " + id + " | Owner: " + currentUser);
    }
}
