package com.shopsphere.controller.dast.api;

import com.shopsphere.service.dast.api.OrderCheckoutService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

/**
 * Controller for DAST API Security benchmark scenarios.
 * Covers BENCH-DAST-019 and BENCH-DAST-020.
 */
@RestController

public class OrderCheckoutController {

    private final OrderCheckoutService service;
    private static final String API_KEY = "secure-api-key-999";

    public OrderCheckoutController(OrderCheckoutService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-019: API Security (Vulnerable Variant)
     * Maps to: GET /api/dast/vulnerable/api-security
     */
    @GetMapping("/api/v1/checkout/place-order")
    public ResponseEntity<Map<String, Object>> getVulnerable() {
        // BENCH-DAST-019
        return ResponseEntity.ok(service.getSystemStats());
    }

    /**
     * BENCH-DAST-020: API Security (Safe Variant)
     * Maps to: GET /api/dast/safe/api-security
     */
    @GetMapping("/api/v1/checkout/place-order/secure")
    public ResponseEntity<Object> getSafe(@RequestHeader(value = "X-API-KEY", required = false) String apiKeyHeader) {
        // BENCH-DAST-020
        if (apiKeyHeader == null || !apiKeyHeader.equals(API_KEY)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("API Key authentication failed: Missing or invalid X-API-KEY header.");
        }
        return ResponseEntity.ok(service.getSystemStats());
    }
}
