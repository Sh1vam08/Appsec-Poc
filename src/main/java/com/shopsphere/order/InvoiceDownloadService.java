package com.shopsphere.service.sast.traversal;

import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Service for Path Traversal benchmark scenarios.
 * Covers BENCH-SAST-049 through BENCH-SAST-052.
 */
@Service
public class InvoiceDownloadService {

    private static final String BASE_DIRECTORY = System.getProperty("user.dir");

    /**
     * BENCH-SAST-049: Path Traversal (Vulnerable Variant)
     * Directly concatenates user input with the base directory to load files.
     */
    public String readFileVulnerable(String filepath) {
        // BENCH-SAST-049
        try {
            File file = new File(BASE_DIRECTORY, filepath);
            // Sink: reading from raw concatenated file path
            return Files.readString(file.toPath());
        } catch (Exception e) {
            return "Path Traversal Execution Fallback: Tried reading file at path " + filepath;
        }
    }

    /**
     * BENCH-SAST-050: Path Traversal (Safe Variant)
     * Resolves the canonical path and checks that it starts with the canonical base directory path.
     */
    public String readFileSafe(String filepath) {
        // BENCH-SAST-050
        try {
            File baseDir = new File(BASE_DIRECTORY);
            File file = new File(baseDir, filepath);
            
            // Canonicalization check
            String canonicalBasePath = baseDir.getCanonicalPath();
            String canonicalFilePath = file.getCanonicalPath();
            
            if (canonicalFilePath.startsWith(canonicalBasePath)) {
                if (file.exists() && !file.isDirectory()) {
                    return Files.readString(file.toPath());
                }
                return "File not found.";
            } else {
                return "Access Denied: Path traversal attempt detected.";
            }
        } catch (IOException e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-051: Path Traversal (Unreachable Variant)
     * Unreachable helper executing vulnerable path traversal logic.
     */
    @SuppressWarnings("unused")
    private String readFileUnreachable(String filepath) {
        // BENCH-SAST-051
        try {
            File file = new File(BASE_DIRECTORY, filepath);
            Files.readString(file.toPath());
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /**
     * BENCH-SAST-052: Path Traversal (Framework-Protected Variant)
     * Validates input parameters using strict regular expressions to block any directory
     * traversal tokens (like "..", "/", or "\").
     */
    public String readFileFrameworkProtected(String filepath) {
        // BENCH-SAST-052
        // Block traversal indicators using a strict filename pattern check
        if (filepath == null || !filepath.matches("^[a-zA-Z0-9_.-]+$")) {
            return "Access Denied: Invalid filepath format.";
        }
        
        try {
            Path path = Paths.get(BASE_DIRECTORY, filepath);
            if (Files.exists(path) && !Files.isDirectory(path)) {
                return Files.readString(path);
            }
            return "File not found.";
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }
}
