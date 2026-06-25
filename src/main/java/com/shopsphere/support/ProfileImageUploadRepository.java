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

    private final String uploadDir = new File("src/main/resources/static/uploads").getAbsolutePath();

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
