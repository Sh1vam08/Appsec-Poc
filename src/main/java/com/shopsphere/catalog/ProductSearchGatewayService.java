package com.shopsphere.service.dast.sqli;

import com.shopsphere.repository.dast.sqli.ProductSearchGatewayRepository;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * Service for DAST SQL Injection benchmark scenarios.
 * Covers BENCH-DAST-001 and BENCH-DAST-002.
 */
@Service
public class ProductSearchGatewayService {

    private final ProductSearchGatewayRepository repository;

    public ProductSearchGatewayService(ProductSearchGatewayRepository repository) {
        this.repository = repository;
    }

    public List<Object[]> queryVulnerable(String username) {
        return repository.executeQueryVulnerable(username);
    }

    public List<Object[]> querySafe(String username) {
        return repository.executeQuerySafe(username);
    }
}
