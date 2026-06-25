package com.shopsphere.cart;

import org.springframework.stereotype.Repository;

/**
 * Repository for DAST CSRF benchmark scenarios.
 * Covers BENCH-DAST-005 and BENCH-DAST-006.
 */
@Repository
public class ShoppingCartRepository {

    private String userEmail = "user@benchmark.local";

    public void updateEmail(String email) {
        this.userEmail = email;
    }

    public String getEmail() {
        return this.userEmail;
    }
}
