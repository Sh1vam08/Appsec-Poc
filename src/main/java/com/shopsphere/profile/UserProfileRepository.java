package com.shopsphere.repository.sast.data;

import com.shopsphere.model.entity.UserProfileData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/**
 * JPA Repository for UserProfileData.
 * Covers BENCH-SAST-077 through BENCH-SAST-080.
 */
@Repository
public interface UserProfileRepository extends JpaRepository<UserProfileData, Long> {
    Optional<UserProfileData> findByUsername(String username);
}
