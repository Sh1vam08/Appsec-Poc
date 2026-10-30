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

    // Use the actual process working directory as the traversal base. When the app runs as a
    // packaged jar (e.g. in the container, workdir /app), "src/main/resources" does not exist, so
    // the OS cannot resolve a "../" path from a non-existent base and the seeded path-traversal
    // flaw becomes unreachable. user.dir always exists, keeping the vulnerable read exercisable.
    private final String baseDir = new File(System.getProperty("user.dir")).getAbsolutePath();

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
