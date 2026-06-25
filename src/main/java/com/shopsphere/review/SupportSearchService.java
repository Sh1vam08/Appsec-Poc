package com.shopsphere.review;

import jakarta.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
import org.springframework.stereotype.Service;
import java.io.IOException;

/**
 * Service for Reflected XSS benchmark scenarios.
 * Covers BENCH-SAST-033 through BENCH-SAST-036.
 */
@Service
public class SupportSearchService {

    /**
     * BENCH-SAST-033: Reflected XSS (Vulnerable Variant)
     * Writes raw user input directly to the HTTP response stream.
     */
    public void writeVulnerable(String input, HttpServletResponse response) throws IOException {
        // BENCH-SAST-033
        response.setContentType("text/html");
        // Sink: HttpServletResponse writer directly printing concatenated raw inputs
        response.getWriter().write("<html><body><h1>Search Result: " + input + "</h1></body></html>");
    }

    /**
     * BENCH-SAST-034: Reflected XSS (Safe Variant)
     * Sanitizes raw user input using the OWASP Java Encoder before writing to the response.
     */
    public void writeSafe(String input, HttpServletResponse response) throws IOException {
        // BENCH-SAST-034
        response.setContentType("text/html");
        String escaped = Encode.forHtml(input);
        response.getWriter().write("<html><body><h1>Search Result: " + escaped + "</h1></body></html>");
    }

    /**
     * BENCH-SAST-035: Reflected XSS (Unreachable Variant)
     * Unreachable helper mapping that writes raw user input directly to response.
     */
    @SuppressWarnings("unused")
    private void writeUnreachable(String input, HttpServletResponse response) throws IOException {
        // BENCH-SAST-035
        response.setContentType("text/html");
        response.getWriter().write("<html><body><h1>Search Result: " + input + "</h1></body></html>");
    }
}
