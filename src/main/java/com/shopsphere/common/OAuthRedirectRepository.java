package com.shopsphere.common;

import org.springframework.stereotype.Repository;
import java.util.ArrayList;
import java.util.List;

/**
 * Repository for DAST Open Redirect benchmark scenarios.
 * Covers BENCH-DAST-009 and BENCH-DAST-010.
 */
@Repository
public class OAuthRedirectRepository {

    private final List<String> redirectHistory = new ArrayList<>();

    public void logRedirect(String url) {
        redirectHistory.add(url);
    }

    public List<String> getRedirectHistory() {
        return new ArrayList<>(redirectHistory);
    }
}
