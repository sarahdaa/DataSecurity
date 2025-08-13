package com.storage.server;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import com.storage.util.EncryptionUtil;

public class PasswordManagerServer {
    private static Map<String, Set<String>> rolePermissions = new HashMap<>();
    private static Map<String, String> userRoles = new HashMap<>();
    private static Map<String, Set<String>> aclPermissions = new HashMap<>();
    private static boolean useACL = false;
    private static final String POLICY_KEY_FILE = "com/storage/server/policy_key.key";

    public static void encryptPolicies() {
        try {
            
            SecretKey key = Files.exists(Paths.get(POLICY_KEY_FILE))
                    ? EncryptionUtil.loadKey(POLICY_KEY_FILE)
                    : EncryptionUtil.generateKey();
    
            if (!Files.exists(Paths.get(POLICY_KEY_FILE))) {
                EncryptionUtil.saveKey(key, POLICY_KEY_FILE);
            }
    
            
            String[] policies = {"acl_policy.txt", "rbac_policy.txt", "user_roles.txt"};
            for (String policy : policies) {
                String path = "com/storage/server/" + policy;
    
              
                if (Files.exists(Paths.get(path))) {
                    String content = new String(Files.readAllBytes(Paths.get(path)));
    
                    
                    if (content.startsWith("ENCRYPTED:")) {
                        System.out.println("File is already encrypted: " + policy);
                        continue;
                    }
    
                    
                    String encryptedContent = "ENCRYPTED:" + EncryptionUtil.encrypt(content, key);
                    Files.write(Paths.get(path), encryptedContent.getBytes());
                    System.out.println("File encrypted: " + policy);
                } else {
                    System.err.println("Policy file not found: " + path);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void decryptPolicies() {
        try {
            
            SecretKey key = EncryptionUtil.loadKey(POLICY_KEY_FILE);
    
            
            String[] policies = {"acl_policy.txt", "rbac_policy.txt", "user_roles.txt"};
            for (String policy : policies) {
                String path = "com/storage/server/" + policy;
    
               
                if (!Files.exists(Paths.get(path))) {
                    System.err.println("Policy file not found: " + path);
                    continue;
                }
    
                String content = new String(Files.readAllBytes(Paths.get(path)));
    
        
                if (content.startsWith("ENCRYPTED:")) {
                    String encryptedContent = content.substring("ENCRYPTED:".length());
                    String decryptedContent = EncryptionUtil.decrypt(encryptedContent, key);
                    Files.write(Paths.get(path), decryptedContent.getBytes());
                    System.out.println("File decrypted: " + policy);
                } else {
                    System.out.println("File is not encrypted: " + policy);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    

public static String readDecryptedPolicy(String filePath) {
    try {
        SecretKey key = EncryptionUtil.loadKey(POLICY_KEY_FILE);
        String encryptedContent = new String(Files.readAllBytes(Paths.get(filePath)));
        if (encryptedContent.startsWith("ENCRYPTED:")) {
            String content = encryptedContent.substring("ENCRYPTED:".length());
            return EncryptionUtil.decrypt(content, key);
        } else {
            return encryptedContent; 
        }
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}

    public static void loadRoles(String filePath) {
        try (InputStream input = PasswordManagerServer.class.getClassLoader().getResourceAsStream(filePath);
             BufferedReader br = new BufferedReader(new InputStreamReader(input))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;

                String[] parts = line.split(":");
                String role = parts[0].trim();
                String[] permissions = parts[1].trim().split(",");
                Set<String> permissionsSet = new HashSet<>();
                for (String permission : permissions) {
                    permissionsSet.add(permission.trim());
                }
                rolePermissions.put(role, permissionsSet);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void loadUserRoles(String filePath) {
        try (InputStream input = PasswordManagerServer.class.getClassLoader().getResourceAsStream(filePath);
             BufferedReader br = new BufferedReader(new InputStreamReader(input))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;

                String[] parts = line.split(":");
                String user = parts[0].trim();
                String role = parts[1].trim();
                userRoles.put(user, role);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

   public static void loadACL(String filePath) {
    try {
        String decryptedContent = readDecryptedPolicy(filePath);
        if (decryptedContent != null) {
            try (BufferedReader br = new BufferedReader(new StringReader(decryptedContent))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("#") || line.trim().isEmpty()) continue;
                    String[] parts = line.split(":");
                    String user = parts[0].trim();
                    String[] permissions = parts[1].trim().split(",");
                    Set<String> permissionsSet = new HashSet<>();
                    for (String permission : permissions) {
                        permissionsSet.add(permission.trim());
                    }
                    aclPermissions.put(user, permissionsSet);
                }
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}


public static boolean hasPermission(String user, String action) {
    if (useACL) {
        Set<String> permissions = aclPermissions.get(user);
        if (permissions == null || !permissions.contains(action)) {
            System.out.println("Unauthorized access: User " + user + " does not have permission for action: " + action);
            return false; 
        }
    } else {
        String role = userRoles.get(user);
        Set<String> permissions = rolePermissions.get(role);
        if (permissions == null || (!permissions.contains(action) && !permissions.contains("ALL"))) {
            System.out.println("Unauthorized access: User " + user + " does not have permission for action: " + action);
            return false; 
        }
    }
    return true; 
}
private static void decryptOnShutdown() {
    try {
        SecretKey key = EncryptionUtil.loadKey(POLICY_KEY_FILE);
        String[] policies = {"acl_policy.txt", "rbac_policy.txt", "user_roles.txt"};

        for (String policy : policies) {
            String path = "com/storage/server/" + policy;

            if (!Files.exists(Paths.get(path))) {
                System.err.println("Policy file not found: " + path);
                continue;
            }

            String content = new String(Files.readAllBytes(Paths.get(path)));

            // Check for the ENCRYPTED marker
            if (content.startsWith("ENCRYPTED:")) {
                String encryptedContent = content.substring("ENCRYPTED:".length());
                String decryptedContent = EncryptionUtil.decrypt(encryptedContent, key);
                Files.write(Paths.get(path), decryptedContent.getBytes());
                System.out.println("Decrypted policy file: " + path);
            } else {
                System.out.println("File is already in plain text: " + path);
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}



    public static void main(String[] args) {
        try {
            encryptPolicies();
            encryptPolicies();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Server shutting down... Decrypting policy files.");
                decryptOnShutdown();
            }));

            PasswordManagerImpl manager = new PasswordManagerImpl();

            // User choice for ACL or RBAC
            useACL = args.length > 0 && args[0].equalsIgnoreCase("acl");
            if (useACL) {
                loadACL("com/storage/server/acl_policy.txt");
                System.out.println("Using Access Control List (ACL)");
            } else {
                loadRoles("com/storage/server/rbac_policy.txt");
                loadUserRoles("com/storage/server/user_roles.txt");
                System.out.println("Using Role-Based Access Control (RBAC)");
            }

            Registry registry = LocateRegistry.createRegistry(1101);
            registry.rebind("PasswordManager", manager);
            System.out.println("Password Manager Server is running...");
            while (true) {
                Thread.sleep(1000);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// ALL RUN FROM demo/src/main/java

// COMPILE: javac com/storage/client/*.java com/storage/server/*.java

// SERVER: java -classpath ".:sqlite-jdbc-3.47.0.0.jar" -Djava.rmi.server.hostname=localhost com.storage.server.PasswordManagerServer

// CLIENT: java -cp ".:sqlite-jdbc-3.47.0.0.jar" com.storage.client.PrintClient