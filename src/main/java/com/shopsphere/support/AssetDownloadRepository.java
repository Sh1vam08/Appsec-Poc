package com.shopsphere.support;

import org.springframework.stereotype.Repository;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * Repository for DAST Path Traversal benchmark scenarios.
 * Covers BENCH-DAST-011 and BENCH-DAST-012.
 */
@Repository
public class AssetDownloadRepository {

    private final String baseDir = new File("src/main/resources").getAbsolutePath();

    public String getBaseDirectory() {
        return baseDir;
    }

    public String readFileContent(File file) throws IOException {
        if (!file.exists()) {
            return "File not found: " + file.getName();
        }
        return new String(Files.readAllBytes(file.toPath()));
    }
}
