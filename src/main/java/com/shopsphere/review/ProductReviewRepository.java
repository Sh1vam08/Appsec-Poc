package com.shopsphere.repository.sast.xss;

import com.shopsphere.model.entity.SecurityAuditReport;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Repository for Stored XSS benchmark scenarios.
 * Uses the H2 database to store and retrieve simulated feedback payloads.
 */
@Repository
public class ProductReviewRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * BENCH-SAST-029: Stored XSS (Vulnerable Variant)
     * Stores the comment exactly as input in the database.
     */
    @Transactional
    public void saveComment(String content) {
        // BENCH-SAST-029
        // We use the description column in vulnerability_reports to store our XSS payload
        entityManager.createNativeQuery(
            "INSERT INTO vulnerability_reports (title, description, severity, status) VALUES ('XSS Feedback', '" + content + "', 'HIGH', 'OPEN')"
        ).executeUpdate();
    }

    /**
     * Retrieve the latest stored comment/feedback.
     */
    public String getLatestComment() {
        try {
            return (String) entityManager.createNativeQuery(
                "SELECT description FROM vulnerability_reports WHERE title = 'XSS Feedback' ORDER BY id DESC LIMIT 1"
            ).getSingleResult();
        } catch (Exception e) {
            return "No feedback comments found.";
        }
    }
}
