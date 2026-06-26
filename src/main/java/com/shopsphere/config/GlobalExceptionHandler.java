package com.shopsphere.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import jakarta.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Global Exception Handler for testing Information Disclosure.
 * BENCH-DAST-025: Information Exposure through an Error Message.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleAllExceptions(Exception ex, HttpServletRequest request) {
        String path = request.getRequestURI();
        
        // BENCH-DAST-025 (Vulnerable)
        // Intentionally leak full stack traces for 'vulnerable' API endpoints
        if (path.contains("/vulnerable/")) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            ex.printStackTrace(pw);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Vulnerable Error Endpoint - Stack Trace Leaked:\n" + sw.toString());
        }
        
        // BENCH-DAST-026 (Safe)
        // Safe endpoints return a generic error message, suppressing the internal stack trace.
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("An unexpected error occurred. Please try again later.");
    }
}
