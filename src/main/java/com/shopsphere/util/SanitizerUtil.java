package com.shopsphere.util;

import java.util.regex.Pattern;

/**
 * BENCH-SAST-FP-001: Custom sanitizer utility
 * Tests: False positive reduction, Custom query/rule engine
 *
 * This is a SAFE sanitizer. If a SAST tool flags code that uses
 * this sanitizer's output as vulnerable, it is a FALSE POSITIVE.
 */
public class SanitizerUtil {

    private static final Pattern SQL_INJECTION_PATTERN = 
        Pattern.compile("[;'\"\\\\]|--|\\/\\*|\\*\\/|\\bOR\\b|\\bAND\\b|\\bUNION\\b|\\bSELECT\\b|\\bDROP\\b|\\bINSERT\\b|\\bDELETE\\b|\\bUPDATE\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern XSS_PATTERN = 
        Pattern.compile("<[^>]*>|javascript:|on\\w+\\s*=", Pattern.CASE_INSENSITIVE);

    /**
     * Sanitizes input against SQL injection patterns.
     * Returns null if malicious content is detected.
     */
    public static String sanitizeSql(String input) {
        if (input == null) return null;
        if (SQL_INJECTION_PATTERN.matcher(input).find()) {
            return null; // Reject malicious input
        }
        return input.trim();
    }

    /**
     * Sanitizes input against XSS patterns.
     * Strips all HTML tags and script content.
     */
    public static String sanitizeXss(String input) {
        if (input == null) return null;
        return input.replaceAll("<[^>]*>", "")
                    .replaceAll("(?i)javascript:", "")
                    .replaceAll("(?i)on\\w+\\s*=", "");
    }

    /**
     * Validates that input contains only alphanumeric characters and spaces.
     */
    public static boolean isAlphanumeric(String input) {
        return input != null && input.matches("^[a-zA-Z0-9 ]+$");
    }
}
