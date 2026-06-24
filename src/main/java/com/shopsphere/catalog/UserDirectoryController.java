package com.shopsphere.controller.sast.injection;

import com.shopsphere.service.sast.injection.UserDirectoryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for LDAP Injection benchmark scenarios.
 * Covers BENCH-SAST-013 through BENCH-SAST-016.
 */
@RestController

public class UserDirectoryController {

    private final UserDirectoryService ldapInjectionService;

    public UserDirectoryController(UserDirectoryService ldapInjectionService) {
        this.ldapInjectionService = ldapInjectionService;
    }

    /**
     * BENCH-SAST-013: LDAP Injection (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/ldap
     */
    @GetMapping("/api/v1/users/lookup")
    public String getVulnerable(@RequestParam String username) {
        return ldapInjectionService.searchVulnerable(username);
    }

    /**
     * BENCH-SAST-014: LDAP Injection (Safe Variant)
     * Maps to: GET /api/safe/ldap
     */
    @GetMapping("/api/v1/users/lookup/secure")
    public String getSafe(@RequestParam String username) {
        return ldapInjectionService.searchSafe(username);
    }

    /**
     * BENCH-SAST-016: LDAP Injection (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/ldap
     */
    @GetMapping("/api/v1/users/lookup/jpa")
    public String getFrameworkProtected(@RequestParam String username) {
        return ldapInjectionService.searchFrameworkProtected(username);
    }
}
