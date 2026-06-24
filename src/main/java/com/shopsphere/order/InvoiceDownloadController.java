package com.shopsphere.controller.sast.traversal;

import com.shopsphere.service.sast.traversal.InvoiceDownloadService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Path Traversal benchmark scenarios.
 * Covers BENCH-SAST-049 through BENCH-SAST-052.
 */
@RestController

public class InvoiceDownloadController {

    private final InvoiceDownloadService pathTraversalService;

    public InvoiceDownloadController(InvoiceDownloadService pathTraversalService) {
        this.pathTraversalService = pathTraversalService;
    }

    /**
     * BENCH-SAST-049: Path Traversal (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/traversal
     */
    @GetMapping("/api/v1/orders/invoice/download")
    public org.springframework.http.ResponseEntity<String> getVulnerable(@RequestParam String filepath) {
        String content = pathTraversalService.readFileVulnerable(filepath);
        return org.springframework.http.ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"product-sheet.txt\"")
                .body(content);
    }

    /**
     * BENCH-SAST-050: Path Traversal (Safe Variant)
     * Maps to: GET /api/safe/traversal
     */
    @GetMapping("/api/v1/orders/invoice/download/secure")
    public String getSafe(@RequestParam String filepath) {
        return pathTraversalService.readFileSafe(filepath);
    }

    /**
     * BENCH-SAST-052: Path Traversal (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/traversal
     */
    @GetMapping("/api/v1/orders/invoice/download/resource")
    public String getFrameworkProtected(@RequestParam String filepath) {
        return pathTraversalService.readFileFrameworkProtected(filepath);
    }
}
