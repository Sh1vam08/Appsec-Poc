package com.shopsphere.catalog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * BENCH-SAST-DEEP-001: Entry point controller (Hop 1 of 4)
 * Tests: Interprocedural analysis, Taint analysis, Source-to-sink tracking
 *
 * User input enters here via @RequestParam and flows through:
 * Controller → Service → DataHandler (interface) → Repository (SQL sink)
 *
 * A SAST tool must trace this 4-hop chain to detect the SQL injection.
 */
@RestController
@RequestMapping("/api/v1/deep")
public class DeepFlowController {

    @Autowired
    private DeepFlowService deepFlowService;

    /**
     * VULNERABLE: User input flows through 4 method calls to reach an SQL sink.
     */
    @GetMapping("/search")
    public String deepSearch(@RequestParam("filter") String filter) {
        // Hop 1: passes user input to the service layer
        return deepFlowService.processUserFilter(filter);
    }
}
