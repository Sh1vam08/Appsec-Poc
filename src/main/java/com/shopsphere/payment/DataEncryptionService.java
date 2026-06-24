package com.shopsphere.service.sast.crypto;

import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service for Weak Cryptography benchmark scenarios.
 * Covers BENCH-SAST-069 through BENCH-SAST-072.
 */
@Service
public class DataEncryptionService {

    /**
     * BENCH-SAST-069: Weak Cryptography (Vulnerable Variant)
     * Uses obsolete and weak DES cipher algorithm.
     */
    public String encryptVulnerable(String text) {
        // BENCH-SAST-069
        try {
            // Sink: instantiating weak cipher instance (DES)
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecretKey key = keyGen.generateKey();
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(text.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            return "Crypto error: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-070: Weak Cryptography (Safe Variant)
     * Uses strong AES cipher in GCM mode with a secure random Initialization Vector (IV).
     */
    public String encryptSafe(String text) {
        // BENCH-SAST-070
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            
            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            // Safe: Uses AES/GCM/NoPadding
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            
            byte[] encrypted = cipher.doFinal(text.getBytes());
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            return "Secure Crypto error: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-071: Weak Cryptography (Unreachable Variant)
     * Unreachable helper initializing weak DES cipher.
     */
    @SuppressWarnings("unused")
    private String encryptUnreachable(String text) {
        // BENCH-SAST-071
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            return cipher.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * BENCH-SAST-072: Weak Cryptography (Framework-Protected Variant)
     * Employs Spring Security's native TextEncryptor wrapper, which internally
     * manages key hashing, secure random salting, and AES-GCM operations.
     */
    public String encryptFrameworkProtected(String text) {
        // BENCH-SAST-072
        // Uses standard Spring Security TextEncryptor
        TextEncryptor encryptor = Encryptors.text("secure_password_key", "5c07472c1c243f9a");
        return encryptor.encrypt(text);
    }
}
