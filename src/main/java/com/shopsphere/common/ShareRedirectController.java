package com.shopsphere.common;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.RedirectView;
import java.io.IOException;

/**
 * Controller for Open Redirect benchmark scenarios.
 * Covers BENCH-SAST-045 through BENCH-SAST-048.
 */
@Controller

public class ShareRedirectController {

    private final ShareRedirectService openRedirectService;

    public ShareRedirectController(ShareRedirectService openRedirectService) {
        this.openRedirectService = openRedirectService;
    }

    /**
     * BENCH-SAST-045: Open Redirect (Vulnerable Variant)
     * Maps to: GET /api/vulnerable/redirect
     */
    @GetMapping("/api/v1/share/redirect")
    public void getVulnerable(@RequestParam String url, HttpServletResponse response) throws IOException {
        openRedirectService.redirectVulnerable(url, response);
    }

    /**
     * BENCH-SAST-046: Open Redirect (Safe Variant)
     * Maps to: GET /api/safe/redirect
     */
    @GetMapping("/api/v1/share/redirect/secure")
    public void getSafe(@RequestParam String url, HttpServletResponse response) throws IOException {
        openRedirectService.redirectSafe(url, response);
    }

    /**
     * BENCH-SAST-048: Open Redirect (Framework-Protected Variant)
     * Maps to: GET /api/framework-protected/redirect
     */
    @GetMapping("/api/v1/share/redirect/relative")
    @ResponseBody
    public RedirectView getFrameworkProtected(@RequestParam String url) {
        return openRedirectService.redirectFrameworkProtected(url);
    }
}
