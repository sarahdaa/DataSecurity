package com.storage.server;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class TokenEncryption {
    private static final String ENCRYPTION_ALGORITHM = "AES"; //define encryption algorithm 
    private static final SecretKey SECRET_KEY = generateKey(); //secret key

    // Generates an encryption key during initialization
    private static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
            keyGen.init(256); // AES-256
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error generating encryption key", e);
        }
    }

    // Encrypting token
    public static String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM); //initializes cipher
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY); //configures cipher
            byte[] encryptedBytes = cipher.doFinal(data.getBytes()); //encrypts data
            return Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedBytes); //Base64
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    // Decrypt token
    public static String decrypt(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM); //initializes cipher
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY); //configures cipher
            byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedData)); //decodes/decrypts data
            return new String(decryptedBytes); //converts back to string
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}

