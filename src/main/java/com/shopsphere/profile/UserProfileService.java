package com.shopsphere.service.sast.data;

import com.shopsphere.model.dto.UserProfileDto;
import com.shopsphere.model.dto.RawUserProfileDto;
import com.shopsphere.model.entity.UserProfileData;
import com.shopsphere.repository.sast.data.UserProfileRepository;
import org.springframework.stereotype.Service;
import java.util.Optional;

/**
 * Service for Sensitive Data Exposure benchmark scenarios.
 * Covers BENCH-SAST-077 through BENCH-SAST-080.
 */
@Service
public class UserProfileService {

    private final UserProfileRepository sensitiveDataRepository;

    public UserProfileService(UserProfileRepository sensitiveDataRepository) {
        this.sensitiveDataRepository = sensitiveDataRepository;
    }

    /**
     * BENCH-SAST-077: Sensitive Data Exposure (Vulnerable Variant)
     * Retrieves sensitive entity and maps to DTO that exposes all PII fields (SSN, credit card).
     */
    public RawUserProfileDto getUserDataVulnerable(String username) {
        // BENCH-SAST-077
        Optional<UserProfileData> dataOpt = sensitiveDataRepository.findByUsername(username);
        return dataOpt.map(data -> new RawUserProfileDto(
            data.getId(),
            data.getUsername(),
            data.getEmail(),
            data.getSsn(),
            data.getCreditCard()
        )).orElse(null);
    }

    /**
     * BENCH-SAST-078: Sensitive Data Exposure (Safe Variant)
     * Maps to a secure DTO excluding SSN and credit card data.
     */
    public UserProfileDto getUserDataSafe(String username) {
        // BENCH-SAST-078
        Optional<UserProfileData> dataOpt = sensitiveDataRepository.findByUsername(username);
        return dataOpt.map(data -> new UserProfileDto(
            data.getId(),
            data.getUsername(),
            data.getEmail()
        )).orElse(null);
    }

    /**
     * BENCH-SAST-079: Sensitive Data Exposure (Unreachable Variant)
     * Unreachable helper mapping sensitive data directly to DTO that exposes PII.
     */
    @SuppressWarnings("unused")
    private RawUserProfileDto getUserDataUnreachable(String username) {
        // BENCH-SAST-079
        Optional<UserProfileData> dataOpt = sensitiveDataRepository.findByUsername(username);
        return dataOpt.map(data -> new RawUserProfileDto(
            data.getId(),
            data.getUsername(),
            data.getEmail(),
            data.getSsn(),
            data.getCreditCard()
        )).orElse(null);
    }

    /**
     * BENCH-SAST-080: Sensitive Data Exposure (Framework-Protected Variant)
     * Returns the UserProfileData entity directly, relying on Jackson's @JsonIgnore
     * to protect sensitive PII fields.
     */
    public UserProfileData getUserDataFrameworkProtected(String username) {
        // BENCH-SAST-080
        return sensitiveDataRepository.findByUsername(username).orElse(null);
    }
}
