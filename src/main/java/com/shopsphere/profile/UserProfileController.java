package com.shopsphere.controller.sast.data;

import com.shopsphere.model.dto.UserProfileDto;
import com.shopsphere.model.dto.RawUserProfileDto;
import com.shopsphere.model.entity.UserProfileData;
import com.shopsphere.service.sast.data.UserProfileService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Sensitive Data Exposure benchmark scenarios.
 * Covers BENCH-SAST-077 through BENCH-SAST-080.
 */
@RestController

public class UserProfileController {

    private final UserProfileService sensitiveDataService;

    public UserProfileController(UserProfileService sensitiveDataService) {
        this.sensitiveDataService = sensitiveDataService;
    }

    /**
     * BENCH-SAST-077: Sensitive Data Exposure (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/data-exposure
     */
    @GetMapping("/api/v1/profile/view")
    public RawUserProfileDto getVulnerable(@RequestParam String username) {
        // BENCH-SAST-077
        return sensitiveDataService.getUserDataVulnerable(username);
    }

    /**
     * BENCH-SAST-078: Sensitive Data Exposure (Safe Variant)
     * Maps to: GET /api/safe/data-exposure
     */
    @GetMapping("/api/v1/profile/view/secure")
    public UserProfileDto getSafe(@RequestParam String username) {
        // BENCH-SAST-078
        return sensitiveDataService.getUserDataSafe(username);
    }

    /**
     * BENCH-SAST-080: Sensitive Data Exposure (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/data-exposure
     */
    @GetMapping("/api/v1/profile/view/projection")
    public UserProfileData getFrameworkProtected(@RequestParam String username) {
        // BENCH-SAST-080
        return sensitiveDataService.getUserDataFrameworkProtected(username);
    }
}
