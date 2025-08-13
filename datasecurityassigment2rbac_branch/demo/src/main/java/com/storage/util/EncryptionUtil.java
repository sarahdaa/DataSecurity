
package com.storage.util;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class EncryptionUtil {

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public static void saveKey(SecretKey key, String filePath) throws Exception {
        byte[] encodedKey = key.getEncoded();
        Files.write(Paths.get(filePath), Base64.getEncoder().encode(encodedKey));
    }

    public static SecretKey loadKey(String filePath) throws Exception {
        byte[] encodedKey = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(filePath)));
        return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decryptedData);
    }
}
