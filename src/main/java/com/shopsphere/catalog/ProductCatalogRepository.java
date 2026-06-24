package com.shopsphere.repository.sast.injection;

import com.shopsphere.model.entity.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;
import java.util.List;

/**
 * Repository for SQL Injection benchmark scenarios.
 * Implements vulnerable (concatenated) and safe (parameterized) database queries.
 */
@Repository
public class ProductCatalogRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * BENCH-SAST-001: SQL Injection (Vulnerable Variant)
     * Concatenates raw user input directly into a SQL statement, causing SQL Injection.
     */
    @SuppressWarnings("unchecked")
    public List<User> searchVulnerable(String username) {
        // BENCH-SAST-001
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return entityManager.createNativeQuery(query, User.class).getResultList();
    }

    /**
     * BENCH-SAST-002: SQL Injection (Safe Variant)
     * Uses JPA named parameters to secure the query against SQL Injection.
     */
    public List<User> searchSafe(String username) {
        // BENCH-SAST-002
        String query = "SELECT u FROM User u WHERE u.username = :username";
        return entityManager.createQuery(query, User.class)
                .setParameter("username", username)
                .getResultList();
    }

    /**
     * BENCH-SAST-003: SQL Injection (Unreachable Variant)
     * This is a private query function that is never called by any endpoint.
     */
    @SuppressWarnings("unused")
    private List<User> searchUnreachable(String username) {
        // BENCH-SAST-003
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return entityManager.createNativeQuery(query, User.class).getResultList();
    }
}
