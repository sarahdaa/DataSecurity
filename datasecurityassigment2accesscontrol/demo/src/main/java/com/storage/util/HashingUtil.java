package com.storage.util;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashingUtil {
    // Generate a secure random salt
    public static byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    // Hash the password with salt using SHA-256
    public static String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt); // Add salt to the hashing process
            byte[] hashedPassword = md.digest(password.getBytes());
            return bytesToHex(salt) + ":" + bytesToHex(hashedPassword); // Store salt and hash
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // Convert bytes to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Validate the password by re-hashing the input and comparing it to the stored hash
    public static boolean validatePassword(String inputPassword, String storedPassword) {
        try {
            String[] parts = storedPassword.split(":");
            byte[] salt = hexToBytes(parts[0]); // Extract salt
            String hashOfInput = hashPassword(inputPassword, salt).split(":")[1]; // Hash input
            return hashOfInput.equals(parts[1]); // Compare hashes
        } catch (Exception e) {
            return false;
        }
    }

    // Convert hexadecimal string back to bytes
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
