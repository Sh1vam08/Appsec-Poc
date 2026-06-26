package com.shopsphere.common;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.StringTemplateResolver;

/**
 * Controller for SSTI (Server-Side Template Injection) benchmark scenarios.
 * BENCH-SAST-101: Server-Side Template Injection (Vulnerable Variant)
 */
@RestController
@RequestMapping("/api/v1/templates")
public class TemplateController {

    private final TemplateEngine templateEngine;

    public TemplateController() {
        this.templateEngine = new TemplateEngine();
        StringTemplateResolver templateResolver = new StringTemplateResolver();
        templateResolver.setTemplateMode(TemplateMode.HTML);
        this.templateEngine.setTemplateResolver(templateResolver);
    }

    /**
     * BENCH-SAST-101: SSTI (Vulnerable Variant)
     * Dynamically processes user input as a Thymeleaf template.
     * Example Attack: /api/v1/templates/render?greeting=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
     */
    @GetMapping("/render")
    public ResponseEntity<String> renderTemplate(@RequestParam String greeting) {
        // BENCH-SAST-101
        // Vulnerable: User input is directly treated as the template structure.
        Context context = new Context();
        context.setVariable("user", "Guest");
        
        try {
            // Sink: process() on a StringTemplateResolver with unvalidated input
            String result = templateEngine.process(greeting, context);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Template error");
        }
    }
}
