package com.shopsphere.review;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * Controller for DAST Cross-Site Scripting (XSS) benchmark scenarios.
 * Covers BENCH-DAST-003 and BENCH-DAST-004.
 */
@RestController

public class FeedbackReviewController {

    private final FeedbackReviewService service;

    public FeedbackReviewController(FeedbackReviewService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-003: XSS (Vulnerable Variant)
     * Maps to: GET /api/dast/vulnerable/xss
     */
    @GetMapping(value = "/api/v1/reviews/feedback", produces = "text/html")
    public String getVulnerable(@RequestParam String input) {
        // BENCH-DAST-003
        service.saveLog(input);
        return "<html><body><h1>Search Results</h1><p>You searched for: " + input + "</p></body></html>";
    }

    /**
     * BENCH-DAST-004: XSS (Safe Variant)
     * Maps to: GET /api/dast/safe/xss
     */
    @GetMapping(value = "/api/v1/reviews/feedback/secure", produces = "text/html")
    public String getSafe(@RequestParam String input) {
        // BENCH-DAST-004
        service.saveLog(input);
        String escaped = HtmlUtils.htmlEscape(input);
        return "<html><body><h1>Search Results</h1><p>You searched for: " + escaped + "</p></body></html>";
    }
}
