package com.shopsphere.service.dast.upload;

import com.shopsphere.repository.dast.upload.ProfileImageUploadRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.io.IOException;
import java.util.UUID;

/**
 * Service for DAST File Upload benchmark scenarios.
 * Covers BENCH-DAST-013 and BENCH-DAST-014.
 */
@Service
public class ProfileImageUploadService {

    private final ProfileImageUploadRepository repository;

    public ProfileImageUploadService(ProfileImageUploadRepository repository) {
        this.repository = repository;
    }

    /**
     * BENCH-DAST-013: File Upload (Vulnerable Variant)
     * Sink: writing file directly with its original filename in static webroot.
     */
    public String uploadFileVulnerable(MultipartFile file) throws IOException {
        // BENCH-DAST-013
        if (file.isEmpty()) {
            return "File is empty";
        }
        String fileName = file.getOriginalFilename();
        if (fileName == null) {
            fileName = "uploaded_file";
        }
        String targetPath = repository.getUploadDirectory() + File.separator + fileName;
        repository.saveFile(file.getBytes(), targetPath);
        return "File uploaded successfully to: " + fileName;
    }

    /**
     * BENCH-DAST-014: File Upload (Safe Variant)
     * Validates file extensions (images only) and sanitizes output file names.
     */
    public String uploadFileSafe(MultipartFile file) throws IOException {
        // BENCH-DAST-014
        if (file.isEmpty()) {
            return "File is empty";
        }
        String fileName = file.getOriginalFilename();
        if (fileName == null) {
            throw new IllegalArgumentException("Invalid filename.");
        }

        // Validate extension
        String lowercaseName = fileName.toLowerCase();
        if (!lowercaseName.endsWith(".jpg") && !lowercaseName.endsWith(".jpeg") && !lowercaseName.endsWith(".png") && !lowercaseName.endsWith(".gif")) {
            throw new IllegalArgumentException("Unsupported file type. Only JPG, PNG, and GIF allowed.");
        }

        // Sanitize path (generate a safe random filename and discard traversal inputs)
        String extension = lowercaseName.substring(lowercaseName.lastIndexOf("."));
        String safeName = UUID.randomUUID().toString() + extension;
        String targetPath = repository.getUploadDirectory() + File.separator + safeName;

        repository.saveFile(file.getBytes(), targetPath);
        return "File uploaded successfully to: " + safeName;
    }
}
