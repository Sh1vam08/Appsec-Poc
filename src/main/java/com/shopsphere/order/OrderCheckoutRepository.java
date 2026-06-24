package com.shopsphere.repository.dast.api;

import org.springframework.stereotype.Repository;
import java.util.HashMap;
import java.util.Map;

/**
 * Repository for DAST API Security benchmark scenarios.
 * Covers BENCH-DAST-019 and BENCH-DAST-020.
 */
@Repository
public class OrderCheckoutRepository {

    public Map<String, Object> getSystemStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("dbConnectionPoolStatus", "ACTIVE");
        stats.put("totalActiveSessions", 142);
        stats.put("heapMemoryUsedBytes", Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory());
        stats.put("benchmarkStatus", "RUNNING");
        return stats;
    }
}
