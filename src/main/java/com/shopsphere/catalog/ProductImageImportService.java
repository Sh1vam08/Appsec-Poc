package com.shopsphere.service.sast.ssrf;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;

/**
 * Service for Server-Side Request Forgery (SSRF) benchmark scenarios.
 * Covers BENCH-SAST-041 through BENCH-SAST-044.
 */
@Service
public class ProductImageImportService {

    /**
     * BENCH-SAST-041: Server-Side Request Forgery (Vulnerable Variant)
     * Directly connects to user-supplied URLs without any domain or IP validation.
     */
    public String requestVulnerable(String urlString) {
        // BENCH-SAST-041
        StringBuilder result = new StringBuilder();
        try {
            // Sink: raw URL connection instantiation
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }
            }
        } catch (Exception e) {
            result.append("SSRF Connection Failed (Expected fallback): ").append(e.getMessage());
        }
        return result.toString();
    }

    /**
     * BENCH-SAST-042: Server-Side Request Forgery (Safe Variant)
     * Restricts HTTP requests strictly to a whitelisted domain list.
     */
    public String requestSafe(String urlString) {
        // BENCH-SAST-042
        // Validation: Whitelist validation
        if (!urlString.startsWith("https://api.github.com/")) {
            return "Domain not allowed (SSRF protection active).";
        }

        StringBuilder result = new StringBuilder();
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }
            }
        } catch (Exception e) {
            result.append("Safe Connection Complete: ").append(e.getMessage());
        }
        return result.toString();
    }

    /**
     * BENCH-SAST-043: Server-Side Request Forgery (Unreachable Variant)
     * Unreachable helper executing vulnerable URL connection logic.
     */
    @SuppressWarnings("unused")
    private String requestUnreachable(String urlString) {
        // BENCH-SAST-043
        try {
            URL url = new URL(urlString);
            url.openConnection().getInputStream().close();
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /**
     * BENCH-SAST-044: Server-Side Request Forgery (Framework-Protected Variant)
     * Resolves the target IP and blocks loopback, private IP ranges, or multicast addresses,
     * protecting internal network services.
     */
    public String requestFrameworkProtected(String urlString) {
        // BENCH-SAST-044
        try {
            URL url = new URL(urlString);
            String host = url.getHost();
            
            // Resolve host IP to block internal network access
            InetAddress inetAddress = InetAddress.getByName(host);
            if (inetAddress.isLoopbackAddress() || inetAddress.isSiteLocalAddress() || inetAddress.isLinkLocalAddress()) {
                return "SSRF Warning: Access to internal IP space blocked.";
            }

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setInstanceFollowRedirects(false); // Disable redirect following to prevent bypasses
            conn.getInputStream().close();
            return "Framework-Protected connection completed successfully.";
        } catch (Exception e) {
            return "SSRF Connection blocked or failed: " + e.getMessage();
        }
    }
}
