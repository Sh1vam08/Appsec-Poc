package com.shopsphere.auth;

import com.shopsphere.model.entity.User;
import com.shopsphere.repository.UserRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/**
 * Repository for DAST Authentication Weakness benchmark scenarios.
 * Covers BENCH-DAST-015 and BENCH-DAST-016.
 */
@Repository
public class MemberLoginRepository {

    private final UserRepository userRepository;

    public MemberLoginRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
