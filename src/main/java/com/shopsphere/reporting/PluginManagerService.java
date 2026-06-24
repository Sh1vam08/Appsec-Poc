package com.shopsphere.service.sast.reflection;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;

/**
 * Service for Unsafe Reflection benchmark scenarios.
 * Covers BENCH-SAST-057 through BENCH-SAST-060.
 */
@Service
public class PluginManagerService {

    private static final List<String> ALLOWED_CLASSES = List.of(
        "com.shopsphere.model.dto.UserDto",
        "com.shopsphere.model.dto.ProductDto"
    );

    private static final Map<String, Class<?>> CLASS_REGISTRY = Map.of(
        "user", com.shopsphere.model.dto.UserDto.class,
        "product", com.shopsphere.model.dto.ProductDto.class
    );

    /**
     * BENCH-SAST-057: Unsafe Reflection (Vulnerable Variant)
     * Directly loads and instantiates a class from a user-supplied class name.
     */
    public Object instantiateVulnerable(String className) {
        // BENCH-SAST-057
        try {
            // Sink: Class.forName with user-controlled class name
            return Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            return "Reflection instance failed: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-058: Unsafe Reflection (Safe Variant)
     * Verifies the target class name against a strict whitelist before instantiation.
     */
    public Object instantiateSafe(String className) {
        // BENCH-SAST-058
        if (!ALLOWED_CLASSES.contains(className)) {
            return "Access Denied: Class name is not whitelisted.";
        }
        
        try {
            return Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            return "Reflection instance failed: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-059: Unsafe Reflection (Unreachable Variant)
     * Unreachable helper executing vulnerable Class.forName instantiation.
     */
    @SuppressWarnings("unused")
    private Object instantiateUnreachable(String className) {
        // BENCH-SAST-059
        try {
            return Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * BENCH-SAST-060: Unsafe Reflection (Framework-Protected Variant)
     * Maps user request keys to pre-registered Class definitions, resolving the target class
     * without direct parameter input strings passing to Class.forName.
     */
    public Object instantiateFrameworkProtected(String key) {
        // BENCH-SAST-060
        Class<?> clazz = CLASS_REGISTRY.get(key.toLowerCase());
        if (clazz == null) {
            return "Unknown key mapping.";
        }
        
        try {
            return clazz.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            return "Instantiation failed: " + e.getMessage();
        }
    }
}
