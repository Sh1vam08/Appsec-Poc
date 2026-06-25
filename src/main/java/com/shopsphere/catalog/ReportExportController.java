package com.shopsphere.catalog;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Command Injection benchmark scenarios.
 * Covers BENCH-SAST-009 through BENCH-SAST-012.
 */
@RestController

public class ReportExportController {

    private final ReportExportService commandInjectionService;

    public ReportExportController(ReportExportService commandInjectionService) {
        this.commandInjectionService = commandInjectionService;
    }

    /**
     * BENCH-SAST-009: Command Injection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/cmd
     */
    @GetMapping("/api/v1/admin/reports/export")
    public String getVulnerable(@RequestParam String filename) {
        return commandInjectionService.executeVulnerable(filename);
    }

    /**
     * BENCH-SAST-010: Command Injection (Safe Variant)
     * Maps to: GET /api/safe/cmd
     */
    @GetMapping("/api/v1/admin/reports/export/secure")
    public String getSafe(@RequestParam String filename) {
        return commandInjectionService.executeSafe(filename);
    }

    /**
     * BENCH-SAST-012: Command Injection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/cmd
     */
    @GetMapping("/api/v1/admin/reports/export/system")
    public String getFrameworkProtected(@RequestParam String filename) {
        return commandInjectionService.executeFrameworkProtected(filename);
    }
}
