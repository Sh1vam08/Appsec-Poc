package com.shopsphere.review;

import org.springframework.stereotype.Repository;
import java.util.ArrayList;
import java.util.List;

/**
 * Repository for DAST XSS benchmark scenarios.
 * Covers BENCH-DAST-003 and BENCH-DAST-004.
 */
@Repository
public class FeedbackReviewRepository {

    private final List<String> logs = new ArrayList<>();

    public void save(String payload) {
        logs.add(payload);
    }

    public List<String> findAll() {
        return new ArrayList<>(logs);
    }
}
