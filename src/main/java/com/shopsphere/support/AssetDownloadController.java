package com.shopsphere.support;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for DAST Path Traversal benchmark scenarios.
 * Covers BENCH-DAST-011 and BENCH-DAST-012.
 */
@RestController

public class AssetDownloadController {

    private final AssetDownloadService service;

    public AssetDownloadController(AssetDownloadService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-011: Path Traversal (Vulnerable Variant)
     * Maps to: GET /api/dast/vulnerable/traversal
     */
    @GetMapping("/api/v1/assets/download")
    public ResponseEntity<String> getVulnerable(@RequestParam String filename) {
        // BENCH-DAST-011
        try {
            String content = service.getFileContentVulnerable(filename);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }

    /**
     * BENCH-DAST-012: Path Traversal (Safe Variant)
     * Maps to: GET /api/dast/safe/traversal
     */
    @GetMapping("/api/v1/assets/download/secure")
    public ResponseEntity<String> getSafe(@RequestParam String filename) {
        // BENCH-DAST-012
        try {
            String content = service.getFileContentSafe(filename);
            return ResponseEntity.ok(content);
        } catch (SecurityException se) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(se.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }
}
