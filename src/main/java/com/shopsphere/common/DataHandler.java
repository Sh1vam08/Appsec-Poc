package com.shopsphere.common;

/**
 * BENCH-SAST-DEEP-001: Deep inter-procedural vulnerability (4-hop chain)
 * Tests: Interprocedural analysis, Dataflow analysis, Source-to-sink tracking
 *
 * User input enters at DeepFlowController → passes to DeepFlowService →
 * routed through DataHandler interface → executes in DeepFlowRepository (SQL sink).
 * SAST tools must trace 4 method calls deep to detect this SQL injection.
 */

/**
 * Interface for data handling — the SAST tool must resolve the concrete implementation.
 */
public interface DataHandler {
    String processQuery(String input);
}
