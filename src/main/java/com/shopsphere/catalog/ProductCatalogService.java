package com.shopsphere.catalog;

import com.shopsphere.model.entity.User;
import com.shopsphere.repository.UserRepository;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * Service for SQL Injection benchmark scenarios.
 */
@Service
public class ProductCatalogService {

    private final ProductCatalogRepository sqlInjectionRepository;
    private final UserRepository userRepository;

    public ProductCatalogService(ProductCatalogRepository sqlInjectionRepository, UserRepository userRepository) {
        this.sqlInjectionRepository = sqlInjectionRepository;
        this.userRepository = userRepository;
    }

    public List<User> searchVulnerable(String username) {
        return sqlInjectionRepository.searchVulnerable(username);
    }

    public List<User> searchSafe(String username) {
        return sqlInjectionRepository.searchSafe(username);
    }

    /**
     * BENCH-SAST-003: SQL Injection (Unreachable Variant)
     * Private helper method that contains a vulnerable SQL data flow but is never executed.
     */
    @SuppressWarnings("unused")
    private List<User> searchUnreachable(String username) {
        // BENCH-SAST-003
        return sqlInjectionRepository.searchVulnerable(username);
    }

    /**
     * BENCH-SAST-004: SQL Injection (Framework-Protected Variant)
     * Calls a Spring Data JPA repository finder method. The underlying framework automatically
     * parameterizes query parameters, preventing SQL injection.
     */
    public List<User> searchFrameworkProtected(String username) {
        // BENCH-SAST-004
        return userRepository.findByUsername(username)
                .map(List::of)
                .orElse(List.of());
    }
}
