package com.shopsphere.common;

import org.springframework.stereotype.Repository;
import java.util.ArrayList;
import java.util.List;

/**
 * Repository for DAST SSRF benchmark scenarios.
 * Covers BENCH-DAST-007 and BENCH-DAST-008.
 */
@Repository
public class VendorWebhookRepository {

    private final List<String> requestsLog = new ArrayList<>();

    public void logRequest(String url) {
        requestsLog.add(url);
    }

    public List<String> getRequestsLog() {
        return new ArrayList<>(requestsLog);
    }
}
