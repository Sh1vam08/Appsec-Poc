package com.shopsphere.common;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

/**
 * Service for DAST SSRF benchmark scenarios.
 * Covers BENCH-DAST-007 and BENCH-DAST-008.
 */
@Service
public class VendorWebhookService {

    private final VendorWebhookRepository repository;

    public VendorWebhookService(VendorWebhookRepository repository) {
        this.repository = repository;
    }

    /**
     * BENCH-DAST-007: SSRF (Vulnerable Variant)
     * Sink: direct HttpURLConnection instantiation on unvalidated input.
     */
    public String fetchUrlVulnerable(String urlStr) {
        // BENCH-DAST-007
        repository.logRequest(urlStr);
        return executeHttpRequest(urlStr);
    }

    /**
     * BENCH-DAST-008: SSRF (Safe Variant)
     * Validates hostname against a restricted allowlist before opening the connection.
     */
    public String fetchUrlSafe(String urlStr) {
        // BENCH-DAST-008
        repository.logRequest(urlStr);
        try {
            URI uri = new URI(urlStr);
            String host = uri.getHost();
            if (host == null || (!host.equals("localhost") && !host.equals("127.0.0.1") && !host.equals("api.benchmark.local"))) {
                return "SSRF Blocked: Host not on the allowlist.";
            }
            return executeHttpRequest(urlStr);
        } catch (Exception e) {
            return "SSRF Blocked: Invalid URL configuration.";
        }
    }

    private String executeHttpRequest(String urlStr) {
        try {
            URL url = new URI(urlStr).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2500);
            conn.setReadTimeout(2500);

            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            }
        } catch (Exception e) {
            return "SSRF Connection attempted: " + e.getMessage();
        }
    }
}
