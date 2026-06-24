package com.shopsphere.service.sast.crypto;

import com.shopsphere.repository.sast.crypto.PaymentGatewayConfigRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.sql.Connection;

/**
 * Service for Hardcoded Credentials benchmark scenarios.
 * Covers BENCH-SAST-073 through BENCH-SAST-076.
 */
@Service
public class PaymentGatewayConfigService {

    private final PaymentGatewayConfigRepository hardcodedCredsRepository;

    @Value("${spring.datasource.password}")
    private String dbPassword;

    public PaymentGatewayConfigService(PaymentGatewayConfigRepository hardcodedCredsRepository) {
        this.hardcodedCredsRepository = hardcodedCredsRepository;
    }

    /**
     * Testing vulnerable path.
     */
    public boolean testConnectionVulnerable() {
        try (Connection conn = hardcodedCredsRepository.getConnectionVulnerable()) {
            return conn != null && !conn.isClosed();
        } catch (Exception e) {
            // Suppress exception for clean response in benchmark environment
            return false;
        }
    }

    /**
     * Testing safe path using externalized configuration.
     */
    public boolean testConnectionSafe() {
        try (Connection conn = hardcodedCredsRepository.getConnectionSafe(dbPassword)) {
            return conn != null && !conn.isClosed();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Testing framework-protected path using auto-configured dataSource bean.
     */
    public boolean testConnectionFrameworkProtected() {
        try (Connection conn = hardcodedCredsRepository.getConnectionFrameworkProtected()) {
            return conn != null && !conn.isClosed();
        } catch (Exception e) {
            return false;
        }
    }
}
