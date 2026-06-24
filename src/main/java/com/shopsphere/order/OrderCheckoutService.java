package com.shopsphere.service.dast.api;

import com.shopsphere.repository.dast.api.OrderCheckoutRepository;
import org.springframework.stereotype.Service;
import java.util.Map;

/**
 * Service for DAST API Security benchmark scenarios.
 * Covers BENCH-DAST-019 and BENCH-DAST-020.
 */
@Service
public class OrderCheckoutService {

    private final OrderCheckoutRepository repository;

    public OrderCheckoutService(OrderCheckoutRepository repository) {
        this.repository = repository;
    }

    public Map<String, Object> getSystemStats() {
        return repository.getSystemStatistics();
    }
}
