package com.shopsphere.service.sast.redirect;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.view.RedirectView;
import java.io.IOException;
import java.net.URI;
import java.util.List;

/**
 * Service for Open Redirect benchmark scenarios.
 * Covers BENCH-SAST-045 through BENCH-SAST-048.
 */
@Service
public class ShareRedirectService {

    private static final List<String> ALLOWED_HOSTS = List.of("benchmark.local", "api.benchmark.local");

    /**
     * BENCH-SAST-045: Open Redirect (Vulnerable Variant)
     * Directly redirects to user-supplied URLs.
     */
    public void redirectVulnerable(String url, HttpServletResponse response) throws IOException {
        // BENCH-SAST-045
        // Sink: raw HttpServletResponse redirect
        response.sendRedirect(url);
    }

    /**
     * BENCH-SAST-046: Open Redirect (Safe Variant)
     * Restricts redirection to relative paths (paths starting with '/' and not '//' or '/\').
     */
    public void redirectSafe(String url, HttpServletResponse response) throws IOException {
        // BENCH-SAST-046
        if (url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/\\")) {
            response.sendRedirect(url);
        } else {
            response.sendRedirect("/error?msg=invalid_redirect");
        }
    }

    /**
     * BENCH-SAST-047: Open Redirect (Unreachable Variant)
     * Unreachable helper mapping doing raw redirects.
     */
    @SuppressWarnings("unused")
    private void redirectUnreachable(String url, HttpServletResponse response) throws IOException {
        // BENCH-SAST-047
        response.sendRedirect(url);
    }

    /**
     * BENCH-SAST-048: Open Redirect (Framework-Protected Variant)
     * Uses Spring's RedirectView while verifying the hostname against an allowlist.
     */
    public RedirectView redirectFrameworkProtected(String url) {
        // BENCH-SAST-048
        RedirectView redirectView = new RedirectView();
        
        try {
            // If relative, it's safe by default
            if (url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/\\")) {
                redirectView.setUrl(url);
                return redirectView;
            }

            URI uri = new URI(url);
            String host = uri.getHost();
            
            // Check if the host is within our allowed whitelist
            if (host != null && ALLOWED_HOSTS.contains(host)) {
                redirectView.setUrl(url);
            } else {
                redirectView.setUrl("/error?msg=forbidden_redirect");
            }
        } catch (Exception e) {
            redirectView.setUrl("/error?msg=error_parsing_redirect");
        }
        
        return redirectView;
    }
}
