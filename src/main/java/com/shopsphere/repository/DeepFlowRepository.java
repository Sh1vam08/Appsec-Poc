package com.shopsphere.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * BENCH-SAST-DEEP-001: The final sink (Hop 4 of 4)
 * Tests: Interprocedural analysis, Dataflow analysis, Source-to-sink tracking
 *
 * This repository receives the user input after 3 intermediate hops
 * and directly concatenates it into an SQL query — SQL Injection.
 */
@Repository
public class DeepFlowRepository {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Vulnerable: directly concatenates the untrusted input into SQL.
     * The input originated from a controller 3 method calls ago.
     */
    public Object executeQuery(String userProvidedFilter) {
        // CWE-89: SQL Injection — user input reaches SQL sink after 4 hops
        String sql = "SELECT * FROM products WHERE category = '" + userProvidedFilter + "'";
        return jdbcTemplate.queryForList(sql);
    }
}
