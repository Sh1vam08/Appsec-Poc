package com.shopsphere.common;

import com.shopsphere.model.dto.UserDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * Service for Unsafe Deserialization benchmark scenarios.
 * Covers BENCH-SAST-053 through BENCH-SAST-056.
 */
@Service
public class SessionRestoreService {

    private final ObjectMapper objectMapper;

    public SessionRestoreService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * BENCH-SAST-053: Unsafe Deserialization (Vulnerable Variant)
     * Deserializes arbitrary Base64 encoded Java serialized objects without class restrictions.
     */
    public Object deserializeVulnerable(String base64Data) {
        // BENCH-SAST-053
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                // Sink: readObject on unrestricted ObjectInputStream
                return ois.readObject();
            }
        } catch (Exception e) {
            return "Deserialization completed (Exception fallback): " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-054: Unsafe Deserialization (Safe Variant)
     * Uses Java's native ObjectInputFilter to restrict deserialization to specified safe classes.
     */
    public Object deserializeSafe(String base64Data) {
        // BENCH-SAST-054
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                // Configure class filter whitelist (only allow UserDto class)
                ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                    "com.shopsphere.model.dto.UserDto;java.lang.*;!*"
                );
                ois.setObjectInputFilter(filter);
                
                return ois.readObject();
            }
        } catch (Exception e) {
            return "Secure Deserialization filtered or failed: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-055: Unsafe Deserialization (Unreachable Variant)
     * Unreachable helper executing vulnerable Java deserialization.
     */
    @SuppressWarnings("unused")
    private Object deserializeUnreachable(String base64Data) {
        // BENCH-SAST-055
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                return ois.readObject();
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * BENCH-SAST-056: Unsafe Deserialization (Framework-Protected Variant)
     * Avoids native Java serialization entirely by parsing inputs via a framework JSON parser (Jackson).
     */
    public UserDto deserializeFrameworkProtected(String jsonData) {
        // BENCH-SAST-056
        try {
            // Uses standard ObjectMapper which is protected against standard gadget chains by default
            return objectMapper.readValue(jsonData, UserDto.class);
        } catch (Exception e) {
            return null;
        }
    }
}
