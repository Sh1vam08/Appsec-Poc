package com.shopsphere.model.entity;

/**
 * POJO for XSS log entries (no JPA database mapping to avoid startup dependencies).
 */
public class ReviewFeedbackLog {
    private String payload;

    public ReviewFeedbackLog() {
    }

    public ReviewFeedbackLog(String payload) {
        this.payload = payload;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}
