package com.shopsphere.catalog;

import com.shopsphere.util.SanitizerUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

/**
 * BENCH-SAST-FP-001: Controller using custom sanitizer (SAFE)
 * Tests: False positive reduction
 *
 * This endpoint uses SanitizerUtil to clean user input before passing
 * it to a query. A SAST tool should NOT flag this as SQL injection
 * because the input is sanitized. If it does, it's a False Positive.
 */
@RestController
@RequestMapping("/api/v1/sanitized")
public class SanitizedSearchController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * SAFE: Input is sanitized before use in SQL query.
     * If flagged, it's a False Positive.
     */
    @GetMapping("/search")
    public Object safeSearch(@RequestParam("q") String query) {
        String sanitized = SanitizerUtil.sanitizeSql(query);
        if (sanitized == null) {
            return "Invalid input detected";
        }
        // This should NOT be flagged — the input has been sanitized
        String sql = "SELECT * FROM products WHERE name = '" + sanitized + "'";
        return jdbcTemplate.queryForList(sql);
    }
}
