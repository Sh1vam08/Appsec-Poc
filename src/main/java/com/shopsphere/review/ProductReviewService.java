package com.shopsphere.service.sast.xss;

import com.shopsphere.repository.sast.xss.ProductReviewRepository;
import org.springframework.stereotype.Service;

/**
 * Service for Stored XSS benchmark scenarios.
 */
@Service
public class ProductReviewService {

    private final ProductReviewRepository storedXssRepository;

    public ProductReviewService(ProductReviewRepository storedXssRepository) {
        this.storedXssRepository = storedXssRepository;
    }

    public void saveComment(String content) {
        storedXssRepository.saveComment(content);
    }

    public String getLatestComment() {
        return storedXssRepository.getLatestComment();
    }
}
