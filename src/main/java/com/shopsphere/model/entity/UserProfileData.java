package com.shopsphere.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

/**
 * UserProfileData Entity
 * Represents user data containing personally identifiable information (PII).
 * Uses @JsonIgnore to demonstrate framework-protected data serialization.
 */
@Entity
@Table(name = "sensitive_users")
public class UserProfileData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, length = 100)
    private String email;

    // Framework-Protected: Jackson will ignore this during serialization
    @JsonIgnore
    @Column(nullable = false, length = 20)
    private String ssn;

    // Framework-Protected: Jackson will ignore this during serialization
    @JsonIgnore
    @Column(name = "credit_card", nullable = false, length = 30)
    private String creditCard;

    public UserProfileData() {
    }

    public UserProfileData(Long id, String username, String email, String ssn, String creditCard) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.ssn = ssn;
        this.creditCard = creditCard;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSsn() {
        return ssn;
    }

    public void setSsn(String ssn) {
        this.ssn = ssn;
    }

    public String getCreditCard() {
        return creditCard;
    }

    public void setCreditCard(String creditCard) {
        this.creditCard = creditCard;
    }
}
