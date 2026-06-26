package com.shopsphere.catalog;

import com.shopsphere.common.DataHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * BENCH-SAST-DEEP-001: Service layer (Hop 2 of 4)
 * Tests: Interprocedural analysis, Dataflow analysis
 *
 * Receives user input from the controller and passes it to
 * a DataHandler interface. The SAST tool must follow the call chain.
 */
@Service
public class DeepFlowService {

    @Autowired
    private DataHandler dataHandler;

    /**
     * Processes the user's filter input.
     * No sanitization — just passes through to the handler.
     */
    public String processUserFilter(String filterInput) {
        // Hop 2: passes tainted data to the interface
        return dataHandler.processQuery(filterInput);
    }
}
