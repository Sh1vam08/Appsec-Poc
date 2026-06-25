package com.shopsphere.catalog;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Service;

/**
 * Service for Spring Expression Language (SpEL) Injection benchmark scenarios.
 * Covers BENCH-SAST-025 through BENCH-SAST-028.
 */
@Service
public class PromoCodeService {

    /**
     * BENCH-SAST-025: SpEL Injection (Vulnerable Variant)
     * Evaluates user input inside a StandardEvaluationContext, allowing full access to reflection and classes.
     */
    public String evaluateVulnerable(String expression) {
        // BENCH-SAST-025
        try {
            ExpressionParser parser = new SpelExpressionParser();
            StandardEvaluationContext context = new StandardEvaluationContext();
            Object result = parser.parseExpression(expression).getValue(context);
            return result != null ? result.toString() : "null";
        } catch (Exception e) {
            return "SpEL evaluation error: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-026: SpEL Injection (Safe Variant)
     * Evaluates user input using a SimpleEvaluationContext, which disables access to Java types,
     * constructors, and reflection.
     */
    public String evaluateSafe(String expression) {
        // BENCH-SAST-026
        try {
            ExpressionParser parser = new SpelExpressionParser();
            // Secure sandbox context context binding
            SimpleEvaluationContext context = SimpleEvaluationContext.forReadWriteDataBinding().build();
            Object result = parser.parseExpression(expression).getValue(context);
            return result != null ? result.toString() : "null";
        } catch (Exception e) {
            return "SpEL evaluation error (restricted): " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-027: SpEL Injection (Unreachable Variant)
     * Unreachable helper evaluating vulnerable SpEL expressions.
     */
    @SuppressWarnings("unused")
    private String evaluateUnreachable(String expression) {
        // BENCH-SAST-027
        try {
            ExpressionParser parser = new SpelExpressionParser();
            StandardEvaluationContext context = new StandardEvaluationContext();
            parser.parseExpression(expression).getValue(context);
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /**
     * BENCH-SAST-028: SpEL Injection (Framework-Protected Variant)
     * Performs regex verification on the expression pattern before executing it with SimpleEvaluationContext.
     */
    public String evaluateFrameworkProtected(String expression) {
        // BENCH-SAST-028
        // Allow only basic dot-separated alphanumeric property pathways (no functions or class indicators)
        if (expression == null || !expression.matches("^[a-zA-Z0-9.]+$")) {
            return "Invalid expression pattern.";
        }
        
        try {
            ExpressionParser parser = new SpelExpressionParser();
            SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
            Object result = parser.parseExpression(expression).getValue(context);
            return result != null ? result.toString() : "null";
        } catch (Exception e) {
            return "SpEL evaluation error (protected): " + e.getMessage();
        }
    }
}
