package com.shopsphere.model.dto;

import java.math.BigDecimal;

/**
 * Product Data Transfer Object
 * Used for transferring product catalog details.
 */
public class ProductDto {

    private Long id;
    private String name;
    private String description;
    private BigDecimal price;
    private String category;

    public ProductDto() {
    }

    public ProductDto(Long id, String name, String description, BigDecimal price, String category) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.price = price;
        this.category = category;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }
}
