package com.shopsphere.repository.dast.authz;

import com.shopsphere.model.entity.SecurityAuditReport;
import com.shopsphere.repository.SecurityAuditReportRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/**
 * Repository for DAST Authorization Weakness benchmark scenarios.
 * Covers BENCH-DAST-017 and BENCH-DAST-018.
 */
@Repository
public class AdminSettingsRepository {

    private final SecurityAuditReportRepository repository;

    public AdminSettingsRepository(SecurityAuditReportRepository repository) {
        this.repository = repository;
    }

    public Optional<SecurityAuditReport> findById(Long id) {
        return repository.findById(id);
    }
}
