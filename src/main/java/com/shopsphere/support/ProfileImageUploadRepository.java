package com.shopsphere.support;

import org.springframework.stereotype.Repository;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Repository for DAST File Upload benchmark scenarios.
 * Covers BENCH-DAST-013 and BENCH-DAST-014.
 */
@Repository
public class ProfileImageUploadRepository {

    // Runtime-writable location so the unrestricted-upload flaw is exercisable even when the app
    // runs as a packaged jar on a read-only container filesystem (src/main/resources is not present
    // there, and the root FS is read-only; java.io.tmpdir maps to the writable /tmp tmpfs). The
    // vulnerable behaviour (attacker-controlled original filename, no validation) is unchanged.
    private final String uploadDir = new File(System.getProperty("java.io.tmpdir"), "shopsphere-uploads").getAbsolutePath();

    public ProfileImageUploadRepository() {
        // Create upload directory if it does not exist
        new File(uploadDir).mkdirs();
    }

    public String getUploadDirectory() {
        return uploadDir;
    }

    public void saveFile(byte[] bytes, String filePathStr) throws IOException {
        Path path = Paths.get(filePathStr);
        Files.write(path, bytes);
    }
}
