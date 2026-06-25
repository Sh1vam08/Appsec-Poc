package com.shopsphere.payment;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Repository for Hardcoded Credentials benchmark scenarios.
 * Covers BENCH-SAST-073 through BENCH-SAST-076.
 */
@Repository
public class PaymentGatewayConfigRepository {

    private final DataSource dataSource;

    @Value("${spring.datasource.url}")
    private String dbUrl;

    @Value("${spring.datasource.username}")
    private String dbUsername;

    public PaymentGatewayConfigRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * BENCH-SAST-073: Hardcoded Credentials (Vulnerable Variant)
     * Sink: DriverManager.getConnection() with hardcoded password literal.
     */
    public Connection getConnectionVulnerable() throws SQLException {
        // BENCH-SAST-073
        // Sink: Hardcoded password literal
        String password = "HardcodedSuperSecretPassword123!";
        return DriverManager.getConnection(dbUrl, dbUsername, password);
    }

    /**
     * BENCH-SAST-074: Hardcoded Credentials (Safe Variant)
     * Uses password passed dynamically (which is retrieved from secure externalized configuration).
     */
    public Connection getConnectionSafe(String password) throws SQLException {
        // BENCH-SAST-074
        return DriverManager.getConnection(dbUrl, dbUsername, password);
    }

    /**
     * BENCH-SAST-075: Hardcoded Credentials (Unreachable Variant)
     * Unreachable helper containing hardcoded credential literal.
     */
    @SuppressWarnings("unused")
    private Connection getConnectionUnreachable() throws SQLException {
        // BENCH-SAST-075
        String password = "UnreachableHardcodedSecret999!";
        return DriverManager.getConnection(dbUrl, dbUsername, password);
    }

    /**
     * BENCH-SAST-076: Hardcoded Credentials (Framework-Protected Variant)
     * Acquires connection directly from the framework-managed DataSource.
     */
    public Connection getConnectionFrameworkProtected() throws SQLException {
        // BENCH-SAST-076
        return dataSource.getConnection();
    }
}
