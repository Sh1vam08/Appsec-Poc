package com.shopsphere.common;

import org.springframework.stereotype.Service;

/**
 * Service for DAST Open Redirect benchmark scenarios.
 * Covers BENCH-DAST-009 and BENCH-DAST-010.
 */
@Service
public class OAuthRedirectService {

    private final OAuthRedirectRepository repository;

    public OAuthRedirectService(OAuthRedirectRepository repository) {
        this.repository = repository;
    }

    public void logRedirect(String url) {
        repository.logRedirect(url);
    }

    /**
     * BENCH-DAST-010: Open Redirect (Safe Variant)
     * Validates redirect target is relative or locally approved before allowing redirection.
     */
    public boolean isValidRedirect(String url) {
        // BENCH-DAST-010
        if (url == null) {
            return false;
        }
        // Safe: Allow relative paths or localhost links only
        return url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/\\");
    }
}
