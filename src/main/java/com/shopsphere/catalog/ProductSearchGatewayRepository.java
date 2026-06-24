package com.shopsphere.repository.dast.sqli;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import java.util.List;

/**
 * Repository for DAST SQL Injection benchmark scenarios.
 * Covers BENCH-DAST-001 and BENCH-DAST-002.
 */
@Repository
public class ProductSearchGatewayRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * BENCH-DAST-001: SQL Injection (Vulnerable Variant)
     * Sink: createNativeQuery with string concatenation
     */
    @SuppressWarnings("unchecked")
    public List<Object[]> executeQueryVulnerable(String queryVal) {
        // BENCH-DAST-001
        String sql = "SELECT * FROM users WHERE username = '" + queryVal + "'";
        Query query = entityManager.createNativeQuery(sql);
        return query.getResultList();
    }

    /**
     * BENCH-DAST-002: SQL Injection (Safe Variant)
     * Uses parameterized query validation
     */
    @SuppressWarnings("unchecked")
    public List<Object[]> executeQuerySafe(String queryVal) {
        // BENCH-DAST-002
        String sql = "SELECT * FROM users WHERE username = :username";
        Query query = entityManager.createNativeQuery(sql);
        query.setParameter("username", queryVal);
        return query.getResultList();
    }
}
