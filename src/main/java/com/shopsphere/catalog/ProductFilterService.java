package com.shopsphere.catalog;

import org.bson.Document;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * Service for NoSQL Injection benchmark scenarios.
 */
@Service
public class ProductFilterService {

    private final ProductFilterRepository noProductCatalogRepository;

    public ProductFilterService(ProductFilterRepository noProductCatalogRepository) {
        this.noProductCatalogRepository = noProductCatalogRepository;
    }

    public List<Document> searchVulnerable(String username) {
        return noProductCatalogRepository.searchVulnerable(username);
    }

    public List<Document> searchSafe(String username) {
        return noProductCatalogRepository.searchSafe(username);
    }

    /**
     * BENCH-SAST-007: NoSQL Injection (Unreachable Variant)
     * Private helper with vulnerable query logic that is never reached.
     */
    @SuppressWarnings("unused")
    private List<Document> searchUnreachable(String username) {
        // BENCH-SAST-007
        return noProductCatalogRepository.searchVulnerable(username);
    }

    /**
     * BENCH-SAST-008: NoSQL Injection (Framework-Protected Variant)
     * Demonstrates a query built using standard Java maps/documents (framework native query parameters)
     * which inherently separates syntax from data.
     */
    public List<Document> searchFrameworkProtected(String username) {
        // BENCH-SAST-008
        // Uses basic document construction (which functions as a safe key-value lookup)
        Document queryDoc = new Document("username", username);
        return List.of(queryDoc.append("role", "USER").append("source", "nosql-framework-protected"));
    }
}
