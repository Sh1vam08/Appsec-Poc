package com.shopsphere.service.dast.csrf;

import com.shopsphere.repository.dast.csrf.ShoppingCartRepository;
import org.springframework.stereotype.Service;

/**
 * Service for DAST CSRF benchmark scenarios.
 * Covers BENCH-DAST-005 and BENCH-DAST-006.
 */
@Service
public class ShoppingCartService {

    private final ShoppingCartRepository repository;

    public ShoppingCartService(ShoppingCartRepository repository) {
        this.repository = repository;
    }

    public void updateEmail(String email) {
        repository.updateEmail(email);
    }

    public String getEmail() {
        return repository.getEmail();
    }
}
