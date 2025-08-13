package com.storage.server;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class TokenEncryption {
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final SecretKey SECRET_KEY = generateKey(); 

    
    private static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
            keyGen.init(256); // AES-256
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error generating encryption key", e);
        }
    }


    public static String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM); 
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY); 
            byte[] encryptedBytes = cipher.doFinal(data.getBytes()); 
            return Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedBytes); 
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    // Decrypt token
    public static String decrypt(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM); 
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY); 
            byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedData)); 
            return new String(decryptedBytes); 
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}

