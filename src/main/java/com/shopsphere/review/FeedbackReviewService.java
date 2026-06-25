package com.shopsphere.review;

import org.springframework.stereotype.Service;
import java.util.List;

/**
 * Service for DAST XSS benchmark scenarios.
 * Covers BENCH-DAST-003 and BENCH-DAST-004.
 */
@Service
public class FeedbackReviewService {

    private final FeedbackReviewRepository repository;

    public FeedbackReviewService(FeedbackReviewRepository repository) {
        this.repository = repository;
    }

    public void saveLog(String input) {
        repository.save(input);
    }

    public List<String> getLogs() {
        return repository.findAll();
    }
}
