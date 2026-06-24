package com.shopsphere.controller.sast.injection;

import com.shopsphere.service.sast.injection.InventoryImportService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for XML External Entity (XXE) Injection benchmark scenarios.
 * Covers BENCH-SAST-021 through BENCH-SAST-024.
 */
@RestController

public class InventoryImportController {

    private final InventoryImportService xxeService;

    public InventoryImportController(InventoryImportService xxeService) {
        this.xxeService = xxeService;
    }

    /**
     * BENCH-SAST-021: XXE Injection (Vulnerable Variant)
     * Maps to: POST /api/vulnerable/xxe
     */
    @PostMapping(value = "/api/v1/inventory/bulk-import", consumes = "application/xml", produces = "text/plain")
    public String getVulnerable(@RequestBody String xmlContent) {
        return xxeService.parseVulnerable(xmlContent);
    }

    /**
     * BENCH-SAST-022: XXE Injection (Safe Variant)
     * Maps to: POST /api/safe/xxe
     */
    @PostMapping(value = "/api/v1/inventory/bulk-import/secure", consumes = "application/xml", produces = "text/plain")
    public String getSafe(@RequestBody String xmlContent) {
        return xxeService.parseSafe(xmlContent);
    }

    /**
     * BENCH-SAST-024: XXE Injection (Framework-Protected Variant)
     * Maps to: POST /api/framework-protected/xxe
     */
    @PostMapping(value = "/api/v1/inventory/bulk-import/json", consumes = "application/xml", produces = "text/plain")
    public String getFrameworkProtected(@RequestBody String xmlContent) {
        return xxeService.parseFrameworkProtected(xmlContent);
    }
}
