package com.shopsphere.system;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

/**
 * BENCH-SAST-SPEL-001: Spring Expression Language (SpEL) Injection
 * Tests: Framework-aware analysis, Semantic code analysis
 *
 * This endpoint evaluates user-controlled input as a SpEL expression,
 * allowing Remote Code Execution. This is a framework-specific vector
 * that many SAST tools miss.
 *
 * CWE-917: Improper Neutralization of Special Elements used in an Expression
 */
@RestController
@RequestMapping("/api/v1/system")
public class SpelInjectionController {

    private final ExpressionParser parser = new SpelExpressionParser();

    /**
     * VULNERABLE: User input evaluated as SpEL expression.
     * Example attack: /api/v1/system/eval?expr=T(java.lang.Runtime).getRuntime().exec('calc')
     */
    @GetMapping("/eval")
    public String evaluateExpression(@RequestParam("expr") String expression) {
        // CWE-917: SpEL Injection — user input directly parsed as expression
        Object result = parser.parseExpression(expression).getValue();
        return "Result: " + result;
    }
}
