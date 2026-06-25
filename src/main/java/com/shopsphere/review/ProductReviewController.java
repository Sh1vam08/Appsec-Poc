package com.shopsphere.review;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controller for Stored XSS benchmark scenarios.
 * Covers BENCH-SAST-029 through BENCH-SAST-032.
 */
@Controller

public class ProductReviewController {

    private final ProductReviewService storedXssService;

    public ProductReviewController(ProductReviewService storedXssService) {
        this.storedXssService = storedXssService;
    }

    /**
     * BENCH-SAST-029: Stored XSS (Vulnerable Variant)
     * Receives feedback, stores it, and renders using unescaped th:utext.
     * Maps to: GET /api/vulnerable/stored-xss
     */
    @GetMapping("/reviews/product")
    public String getVulnerable(@RequestParam String comment, Model model) {
        storedXssService.saveComment(comment);
        String latestComment = storedXssService.getLatestComment();
        model.addAttribute("comment", latestComment);
        return "xss_vulnerable";
    }

    /**
     * BENCH-SAST-030: Stored XSS (Safe Variant)
     * Receives feedback, stores it, and renders using escaped th:text.
     * Maps to: GET /api/safe/stored-xss
     */
    @GetMapping("/reviews/product/secure")
    public String getSafe(@RequestParam String comment, Model model) {
        // Safe variant: sanitizes the input or relies on safe rendering (th:text)
        storedXssService.saveComment(comment);
        String latestComment = storedXssService.getLatestComment();
        model.addAttribute("comment", latestComment);
        return "xss_safe";
    }

    /**
     * BENCH-SAST-031: Stored XSS (Unreachable Variant)
     * Unreachable helper mapping that saves comments but is never accessed.
     */
    @SuppressWarnings("unused")
    private String getUnreachable(String comment, Model model) {
        // BENCH-SAST-031
        storedXssService.saveComment(comment);
        model.addAttribute("comment", comment);
        return "xss_vulnerable";
    }

    /**
     * BENCH-SAST-032: Stored XSS (Framework-Protected Variant)
     * Maps to: GET /reviews/product/csp
     */
    @GetMapping("/reviews/product/csp")
    public String getFrameworkProtected(@RequestParam String comment, Model model) {
        storedXssService.saveComment(comment);
        String latestComment = storedXssService.getLatestComment();
        model.addAttribute("comment", latestComment);
        return "xss_safe";
    }
}
