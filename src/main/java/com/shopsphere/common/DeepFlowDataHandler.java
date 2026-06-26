package com.shopsphere.common;

import com.shopsphere.repository.DeepFlowRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * BENCH-SAST-DEEP-001: Concrete handler (Hop 3 of 4)
 * Tests: Interprocedural analysis, Framework-aware analysis
 *
 * Implements the DataHandler interface. The SAST tool must resolve
 * this concrete implementation to trace through the interface dispatch.
 */
@Component
public class DeepFlowDataHandler implements DataHandler {

    @Autowired
    private DeepFlowRepository repository;

    @Override
    public String processQuery(String input) {
        // Passes the tainted input to the repository without any sanitization
        Object result = repository.executeQuery(input);
        return result != null ? result.toString() : "No results";
    }
}
