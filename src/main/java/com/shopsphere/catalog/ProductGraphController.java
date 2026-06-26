package com.shopsphere.catalog;

import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.stereotype.Controller;
import java.util.Collections;
import java.util.List;

/**
 * Controller for GraphQL benchmark scenarios.
 * BENCH-DAST-097: GraphQL Authorization / IDOR
 * BENCH-DAST-098: GraphQL Denial of Service (Deep Nesting)
 */
@Controller
public class ProductGraphController {

    @QueryMapping
    public Product product(@Argument String id) {
        // BENCH-DAST-097
        // Vulnerable: Returns product data directly based on user input without any access control check.
        // It also does not limit the depth of queries.
        return new Product(id, "Mock Product " + id, 99.99, "Description for " + id);
    }

    @SchemaMapping
    public List<Product> relatedProducts(Product product) {
        // BENCH-DAST-098
        // Vulnerable: Allows an attacker to craft a recursive, infinitely deep GraphQL query
        // product -> relatedProducts -> relatedProducts -> relatedProducts (DoS)
        return Collections.singletonList(new Product(product.id() + "_related", "Related " + product.name(), 10.0, ""));
    }

    public record Product(String id, String name, double price, String description) {}
}
