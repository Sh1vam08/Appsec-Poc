package com.shopsphere.service.sast.injection;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Service for Command Injection benchmark scenarios.
 */
@Service
public class ReportExportService {

    /**
     * BENCH-SAST-009: Command Injection (Vulnerable Variant)
     * Executes shell command built by string concatenation.
     */
    public String executeVulnerable(String filename) {
        // BENCH-SAST-009
        StringBuilder output = new StringBuilder();
        try {
            String cmd;
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                cmd = "cmd.exe /c type " + filename;
            } else {
                cmd = "sh -c cat " + filename;
            }
            
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
        } catch (Exception e) {
            output.append("Error executing command: ").append(e.getMessage());
        }
        return output.toString();
    }

    /**
     * BENCH-SAST-010: Command Injection (Safe Variant)
     * Avoids OS command execution altogether by using standard Java Files API to read files.
     */
    public String executeSafe(String filename) {
        // BENCH-SAST-010
        try {
            // Input validation and sandbox check to restrict access
            if (!filename.matches("^[a-zA-Z0-9_.-]+$")) {
                return "Invalid filename pattern.";
            }
            
            Path path = Paths.get(filename);
            if (Files.exists(path) && !Files.isDirectory(path)) {
                return Files.readString(path);
            }
            return "File does not exist or access denied.";
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-011: Command Injection (Unreachable Variant)
     * Unreachable method executing concatenated OS commands.
     */
    @SuppressWarnings("unused")
    private String executeUnreachable(String filename) {
        // BENCH-SAST-011
        try {
            String cmd = "cmd.exe /c type " + filename;
            Process process = Runtime.getRuntime().exec(cmd);
            process.waitFor();
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /**
     * BENCH-SAST-012: Command Injection (Framework-Protected Variant)
     * Executes the binary directly using ProcessBuilder list arguments without invoking a shell,
     * preventing arguments from being interpreted as shell commands.
     */
    public String executeFrameworkProtected(String filename) {
        // BENCH-SAST-012
        StringBuilder output = new StringBuilder();
        try {
            // Validate input format to be safe
            if (!filename.matches("^[a-zA-Z0-9_.-]+$")) {
                return "Invalid filename pattern.";
            }

            List<String> cmd = new ArrayList<>();
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                cmd.add("cmd.exe");
                cmd.add("/c");
                cmd.add("type");
                cmd.add(filename);
            } else {
                cmd.add("cat");
                cmd.add(filename);
            }

            // ProcessBuilder processes arguments as distinct parameters rather than evaluating in shell
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
        } catch (Exception e) {
            output.append("Error executing safe command: ").append(e.getMessage());
        }
        return output.toString();
    }
}
