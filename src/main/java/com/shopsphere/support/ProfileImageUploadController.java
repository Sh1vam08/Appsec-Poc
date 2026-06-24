package com.shopsphere.controller.dast.upload;

import com.shopsphere.service.dast.upload.ProfileImageUploadService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * Controller for DAST File Upload benchmark scenarios.
 * Covers BENCH-DAST-013 and BENCH-DAST-014.
 */
@RestController

public class ProfileImageUploadController {

    private final ProfileImageUploadService service;

    public ProfileImageUploadController(ProfileImageUploadService service) {
        this.service = service;
    }

    /**
     * BENCH-DAST-013: File Upload (Vulnerable Variant)
     * Maps to: POST /api/dast/vulnerable/upload
     */
    @PostMapping("/api/v1/profile/avatar/upload")
    public ResponseEntity<String> uploadVulnerable(@RequestParam("file") MultipartFile file) {
        // BENCH-DAST-013
        try {
            String result = service.uploadFileVulnerable(file);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Upload failed: " + e.getMessage());
        }
    }

    /**
     * BENCH-DAST-014: File Upload (Safe Variant)
     * Maps to: POST /api/dast/safe/upload
     */
    @PostMapping("/api/v1/profile/avatar/upload/secure")
    public ResponseEntity<String> uploadSafe(@RequestParam("file") MultipartFile file) {
        // BENCH-DAST-014
        try {
            String result = service.uploadFileSafe(file);
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException iae) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(iae.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Upload failed: " + e.getMessage());
        }
    }
}
