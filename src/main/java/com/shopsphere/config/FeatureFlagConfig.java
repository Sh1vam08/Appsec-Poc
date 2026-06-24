package com.shopsphere.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Feature Flag Configuration
 * Binds custom benchmark execution properties under the prefix "benchmark.feature-flags".
 * These flags are used in subsequent phases to toggle reachability of code paths.
 */
@Configuration
@ConfigurationProperties(prefix = "benchmark.feature-flags")
public class FeatureFlagConfig {

    private boolean sastUnreachableEnabled = false;
    private boolean dastUnreachableEnabled = false;
    private boolean debugMode = false;

    public boolean isSastUnreachableEnabled() {
        return sastUnreachableEnabled;
    }

    public void setSastUnreachableEnabled(boolean sastUnreachableEnabled) {
        this.sastUnreachableEnabled = sastUnreachableEnabled;
    }

    public boolean isDastUnreachableEnabled() {
        return dastUnreachableEnabled;
    }

    public void setDastUnreachableEnabled(boolean dastUnreachableEnabled) {
        this.dastUnreachableEnabled = dastUnreachableEnabled;
    }

    public boolean isDebugMode() {
        return debugMode;
    }

    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }
}
