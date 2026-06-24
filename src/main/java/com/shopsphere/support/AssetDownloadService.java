package com.shopsphere.service.dast.traversal;

import com.shopsphere.repository.dast.traversal.AssetDownloadRepository;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;

/**
 * Service for DAST Path Traversal benchmark scenarios.
 * Covers BENCH-DAST-011 and BENCH-DAST-012.
 */
@Service
public class AssetDownloadService {

    private final AssetDownloadRepository repository;

    public AssetDownloadService(AssetDownloadRepository repository) {
        this.repository = repository;
    }

    /**
     * BENCH-DAST-011: Path Traversal (Vulnerable Variant)
     * Sink: reading file contents from raw concatenated user input.
     */
    public String getFileContentVulnerable(String filename) throws IOException {
        // BENCH-DAST-011
        String filePath = repository.getBaseDirectory() + File.separator + filename;
        File file = new File(filePath);
        return repository.readFileContent(file);
    }

    /**
     * BENCH-DAST-012: Path Traversal (Safe Variant)
     * Validates that resolved canonical path resides inside base directory boundaries.
     */
    public String getFileContentSafe(String filename) throws IOException {
        // BENCH-DAST-012
        String baseDir = repository.getBaseDirectory();
        String filePath = baseDir + File.separator + filename;
        File file = new File(filePath);

        // Safe: Canonicalize and verify directory boundary
        String canonicalPath = file.getCanonicalPath();
        String canonicalBase = new File(baseDir).getCanonicalPath();

        if (!canonicalPath.startsWith(canonicalBase)) {
            throw new SecurityException("Directory Traversal Attempt Blocked.");
        }

        return repository.readFileContent(file);
    }
}
