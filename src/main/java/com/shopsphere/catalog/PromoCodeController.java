package com.shopsphere.controller.sast.injection;

import com.shopsphere.service.sast.injection.PromoCodeService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for SpEL Injection benchmark scenarios.
 * Covers BENCH-SAST-025 through BENCH-SAST-028.
 */
@RestController

public class PromoCodeController {

    private final PromoCodeService spelInjectionService;

    public PromoCodeController(PromoCodeService spelInjectionService) {
        this.spelInjectionService = spelInjectionService;
    }

    /**
     * BENCH-SAST-025: SpEL Injection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/spel
     */
    @GetMapping("/api/v1/promotions/apply")
    public String getVulnerable(@RequestParam String expression) {
        return spelInjectionService.evaluateVulnerable(expression);
    }

    /**
     * BENCH-SAST-026: SpEL Injection (Safe Variant)
     * Maps to: GET /api/safe/spel
     */
    @GetMapping("/api/v1/promotions/apply/secure")
    public String getSafe(@RequestParam String expression) {
        return spelInjectionService.evaluateSafe(expression);
    }

    /**
     * BENCH-SAST-028: SpEL Injection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/spel
     */
    @GetMapping("/api/v1/promotions/apply/bind")
    public String getFrameworkProtected(@RequestParam String expression) {
        return spelInjectionService.evaluateFrameworkProtected(expression);
    }
}
