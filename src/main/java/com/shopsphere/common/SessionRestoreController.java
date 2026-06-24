package com.shopsphere.controller.sast.deserialization;

import com.shopsphere.model.dto.UserDto;
import com.shopsphere.service.sast.deserialization.SessionRestoreService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Unsafe Deserialization benchmark scenarios.
 * Covers BENCH-SAST-053 through BENCH-SAST-056.
 */
@RestController

public class SessionRestoreController {

    private final SessionRestoreService deserializationService;

    public SessionRestoreController(SessionRestoreService deserializationService) {
        this.deserializationService = deserializationService;
    }

    /**
     * BENCH-SAST-053: Unsafe Deserialization (Vulnerable Variant)
     * Maps to: POST /api/vulnerable/deser
     */
    @PostMapping(value = "/api/v1/session/restore", consumes = "text/plain", produces = "text/plain")
    public String postVulnerable(@RequestBody String base64Data) {
        Object obj = deserializationService.deserializeVulnerable(base64Data);
        return obj != null ? "Deserialized class: " + obj.getClass().getName() : "null";
    }

    /**
     * BENCH-SAST-054: Unsafe Deserialization (Safe Variant)
     * Maps to: POST /api/safe/deser
     */
    @PostMapping(value = "/api/v1/session/restore/secure", consumes = "text/plain", produces = "text/plain")
    public String postSafe(@RequestBody String base64Data) {
        Object obj = deserializationService.deserializeSafe(base64Data);
        return obj != null ? "Deserialized class safely: " + obj.getClass().getName() : "null";
    }

    /**
     * BENCH-SAST-056: Unsafe Deserialization (Framework-Protected Variant)
     * Maps to: POST /api/framework-protected/deser
     */
    @PostMapping(value = "/api/v1/session/restore/json", consumes = "application/json", produces = "application/json")
    public UserDto postFrameworkProtected(@RequestBody String jsonData) {
        return deserializationService.deserializeFrameworkProtected(jsonData);
    }
}
