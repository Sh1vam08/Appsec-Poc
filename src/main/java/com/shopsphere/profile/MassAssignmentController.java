package com.shopsphere.profile;

import org.springframework.web.bind.annotation.*;

/**
 * BENCH-SAST-MASS-001: Mass Assignment / Autobinding vulnerability
 * Tests: Framework-aware analysis, API security analysis
 *
 * Spring's @ModelAttribute automatically binds ALL request parameters
 * to the object's fields. An attacker can set fields like "isAdmin"
 * or "role" that should not be user-controllable.
 *
 * CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
 */
@RestController
@RequestMapping("/api/v1/profile")
public class MassAssignmentController {

    /**
     * VULNERABLE: @ModelAttribute binds all request params to UserProfile,
     * including sensitive fields like 'role' and 'isAdmin'.
     * Example attack: POST /api/v1/profile/update?name=John&isAdmin=true&role=ADMIN
     */
    @PostMapping("/update")
    public String updateProfile(@ModelAttribute UserProfile profile) {
        // The attacker can set isAdmin=true and role=ADMIN via request params
        return "Profile updated: " + profile.getName() +
               ", Admin: " + profile.isAdmin() +
               ", Role: " + profile.getRole();
    }

    /**
     * Inner class representing a user profile with sensitive fields.
     */
    public static class UserProfile {
        private String name;
        private String email;
        private boolean isAdmin = false;  // Should NOT be user-settable
        private String role = "USER";     // Should NOT be user-settable
        private double accountBalance;    // Should NOT be user-settable

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public boolean isAdmin() { return isAdmin; }
        public void setIsAdmin(boolean isAdmin) { this.isAdmin = isAdmin; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
        public double getAccountBalance() { return accountBalance; }
        public void setAccountBalance(double accountBalance) { this.accountBalance = accountBalance; }
    }
}
