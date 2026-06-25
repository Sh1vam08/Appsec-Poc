package com.shopsphere.review;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import java.io.IOException;

/**
 * Controller for Reflected XSS benchmark scenarios.
 * Covers BENCH-SAST-033 through BENCH-SAST-036.
 */
@Controller

public class SupportSearchController {

    private final SupportSearchService reflectedXssService;

    public SupportSearchController(SupportSearchService reflectedXssService) {
        this.reflectedXssService = reflectedXssService;
    }

    /**
     * BENCH-SAST-033: Reflected XSS (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/reflected-xss
     */
    @GetMapping("/api/v1/support/query")
    public void getVulnerable(@RequestParam String input, HttpServletResponse response) throws IOException {
        reflectedXssService.writeVulnerable(input, response);
    }

    /**
     * BENCH-SAST-034: Reflected XSS (Safe Variant)
     * Maps to: GET /api/safe/reflected-xss
     */
    @GetMapping("/api/v1/support/query/secure")
    public void getSafe(@RequestParam String input, HttpServletResponse response) throws IOException {
        reflectedXssService.writeSafe(input, response);
    }

    /**
     * BENCH-SAST-036: Reflected XSS (Framework-Protected Variant)
     * Returning a plain string via @ResponseBody defaults the response content-type to
     * text/plain, preventing browser parsing/execution of script payloads.
     * Maps to: GET /api/framework-protected/reflected-xss
     */
    @GetMapping("/api/v1/support/query/json")
    @ResponseBody
    public String getFrameworkProtected(@RequestParam String input) {
        // BENCH-SAST-036
        return "Search Result: " + input;
    }
}
