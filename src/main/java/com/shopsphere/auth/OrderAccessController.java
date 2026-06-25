package com.shopsphere.auth;

import com.shopsphere.model.dto.UserDto;
import com.shopsphere.model.entity.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for Broken Authorization (IDOR) benchmark scenarios.
 * Covers BENCH-SAST-065 through BENCH-SAST-068.
 */
@RestController

public class OrderAccessController {

    private final OrderAccessService brokenAuthzService;

    public OrderAccessController(OrderAccessService brokenAuthzService) {
        this.brokenAuthzService = brokenAuthzService;
    }

    /**
     * BENCH-SAST-065: Broken Authorization (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/broken-authz
     */
    @GetMapping("/api/v1/orders/access")
    public UserDto getVulnerable(@RequestParam Long userId) {
        User user = brokenAuthzService.getUserDataVulnerable(userId);
        return convertToDto(user);
    }

    /**
     * BENCH-SAST-066: Broken Authorization (Safe Variant)
     * Maps to: GET /api/safe/broken-authz
     */
    @GetMapping("/api/v1/orders/access/secure")
    public UserDto getSafe(@RequestParam Long userId) {
        User user = brokenAuthzService.getUserDataSafe(userId);
        return convertToDto(user);
    }

    /**
     * BENCH-SAST-068: Broken Authorization (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/broken-authz
     */
    @GetMapping("/api/v1/orders/access/method")
    public UserDto getFrameworkProtected(@RequestParam String username) {
        User user = brokenAuthzService.getUserDataFrameworkProtected(username);
        return convertToDto(user);
    }

    private UserDto convertToDto(User user) {
        if (user == null) return null;
        return new UserDto(user.getId(), user.getUsername(), user.getEmail(), user.getRole(), user.getCreatedAt());
    }
}
