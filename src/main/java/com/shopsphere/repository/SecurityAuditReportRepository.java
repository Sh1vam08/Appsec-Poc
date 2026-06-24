package com.shopsphere.repository;

import com.shopsphere.model.entity.SecurityAuditReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

/**
 * SecurityAuditReportRepository interface for querying vulnerability reports.
 */
@Repository
public interface SecurityAuditReportRepository extends JpaRepository<SecurityAuditReport, Long> {
    List<SecurityAuditReport> findBySeverity(String severity);
    List<SecurityAuditReport> findByStatus(String status);
}
