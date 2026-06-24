package com.shopsphere.model.dto;

/**
 * DTO representing unfiltered sensitive user data (Vulnerable Variant).
 * Intentionally exposes SSN and credit card fields without serialization protection.
 */
public class RawUserProfileDto {

    private Long id;
    private String username;
    private String email;
    private String ssn;
    private String creditCard;

    public RawUserProfileDto() {
    }

    public RawUserProfileDto(Long id, String username, String email, String ssn, String creditCard) {
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
