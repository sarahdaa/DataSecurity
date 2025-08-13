package com.storage.server;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.storage.server.TokenEncryption;

import com.storage.util.HashingUtil;

public class PasswordManagerImpl extends UnicastRemoteObject implements PasswordManager {
    private static final String DB_URL = "jdbc:sqlite:user_management.db";
    @SuppressWarnings("unused")
    private boolean serverRunning = false;
    private final long SESSION_TIMEOUT = 5 * 60 * 1000;
    private Map<String, Long> activeSessions = new HashMap<>();
    private Map<String, String> sessionUserMap = new HashMap<>(); 

    protected PasswordManagerImpl() throws RemoteException {
        super();
        initializeDatabase();
    }

    private void initializeDatabase() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            String createTableSQL = "CREATE TABLE IF NOT EXISTS users (" +
                    "username TEXT PRIMARY KEY, " +
                    "password TEXT NOT NULL)";
            stmt.execute(createTableSQL);
            System.out.println("Table 'users' checked/created successfully.");
        } catch (SQLException e) {
            System.err.println("Error initializing the database.");
            e.printStackTrace();
        }
    }

    // Database connection
    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private String validateSession(String encryptedToken) throws RemoteException {
        String decryptedToken = TokenEncryption.decrypt(encryptedToken); 
        Long expirationTime = activeSessions.get(decryptedToken); 
    
        if (expirationTime == null) { 
            throw new RemoteException("Session token not found. Please log in again.");
        }
    
        if (System.currentTimeMillis() > expirationTime) { // Check if the token has expired
            activeSessions.remove(decryptedToken); // Remove expired token
            sessionUserMap.remove(decryptedToken);
            throw new RemoteException("Session expired. Please log in again.");
        }
    
        // Renew session expiration time
        activeSessions.put(decryptedToken, System.currentTimeMillis() + SESSION_TIMEOUT);
        return sessionUserMap.get(decryptedToken); 
    }
    
    private void checkPermission(String encryptedToken, String action) throws RemoteException {
        String user = validateSession(encryptedToken); 
    
       
        Set<String> userRoles = PasswordManagerServer.getUserRoles(user);
        if (userRoles == null || userRoles.isEmpty()) {
            throw new RemoteException("Access denied for user: " + user + ". No roles assigned.");
        }
    
        // Aggregate permissions from all roles
        Set<String> aggregatedPermissions = new HashSet<>();
        for (String role : userRoles) {
            Set<String> rolePermissions = PasswordManagerServer.getRolePermissions(role);
            if (rolePermissions != null) {
                aggregatedPermissions.addAll(rolePermissions);
            }
        }
    
        System.out.println("Aggregated permissions for user " + user + ": " + aggregatedPermissions); // Debugging
    
        
        if (!aggregatedPermissions.contains(action) && !aggregatedPermissions.contains("ALL")) {
            throw new RemoteException("Access denied for user: " + user + " for action: " + action);
        }
    }
    
    
    

    
    
    private String hashPassword(String plainPassword) {
    try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(plainPassword.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("Error hashing password", e);
    }
}
private String generateSecureSessionToken() { //GENERATE SESSIONTOKEN
    SecureRandom secureRandom = new SecureRandom(); // initializes a secure random number generator
    byte[] randomBytes = new byte[32]; // 256-bit token (32 bytes) (Creates a byte array)
    secureRandom.nextBytes(randomBytes); // fills the byte array
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes); // encodes the byte array into a Base64 string
}

@Override
public boolean authenticateUser(String username, String plainPassword) throws RemoteException {
    String query = "SELECT password FROM users WHERE username = ?";
    try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(query)) {
        stmt.setString(1, username);
        try (ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                String storedPassword = rs.getString("password");
                return hashPassword(plainPassword).equals(storedPassword); // compare hashed passwords
            }
        }
    } catch (SQLException e) {
        System.err.println("Error during authentication.");
        e.printStackTrace();
    }
    return false;
}


@Override
public boolean updatePassword(String username, String oldPassword, String newPassword) throws RemoteException {
    if (authenticateUser(username, oldPassword)) {
        String query = "UPDATE users SET password = ? WHERE username = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, hashPassword(newPassword)); // Hash the new password
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error updating password.");
            e.printStackTrace();
        }
    } else {
        System.err.println("Old password is incorrect.");
    }
    return false;
}

    
    public boolean addUser(String username, String plainPassword) throws RemoteException {
        String query = "INSERT INTO users (username, password) VALUES (?, ?)";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, hashPassword(plainPassword)); // Store hashed password
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error adding user.");
            e.printStackTrace();
            return false;
        }
    }


    @Override
    public boolean deleteUser(String username) throws RemoteException {
        String query = "DELETE FROM users WHERE username = ?";

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setString(1, username);
            int rowsAffected = stmt.executeUpdate();

            return rowsAffected > 0;
        } catch (SQLException e) {
            System.err.println("Error deleting user.");
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public String login(String username, String password) throws RemoteException {
        if (authenticateUser(username, password)) {
            String sessionToken = generateSecureSessionToken(); // Generate a session token
            String encryptedToken = TokenEncryption.encrypt(sessionToken); // Encrypt token for the client
    
            activeSessions.put(sessionToken, System.currentTimeMillis() + SESSION_TIMEOUT); // Store decrypted token
            sessionUserMap.put(sessionToken, username);
            System.out.println("Login successful. Session token (encrypted): " + encryptedToken);
            System.out.println("Session token (not encrypted): " + sessionToken);
            return encryptedToken; // Return the encrypted token to the client
        }
        throw new RemoteException("Invalid username or password.");
    }
    

    @Override
    public void logout(String sessionToken) throws RemoteException {
        if (activeSessions.remove(sessionToken) != null) { 
            System.out.println("Session " + sessionToken + " has been logged out.");
        } else {
            System.out.println("Invalid session token. Logout failed.");
        }
    }

    @Override
    public boolean isDatabaseEmpty() throws RemoteException {
        String query = "SELECT COUNT(*) AS total FROM users";

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(query);
             ResultSet rs = stmt.executeQuery()) {

            if (rs.next()) {
                int total = rs.getInt("total");
                return total == 0;
            }
        } catch (SQLException e) {
            System.err.println("Error checking if database is empty.");
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public void clearUsers() throws RemoteException {
        String query = "DELETE FROM users";

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.executeUpdate();
            System.out.println("All users cleared from the database.");
        } catch (SQLException e) {
            System.err.println("Error clearing users.");
            e.printStackTrace();
        }
    }

    @Override
    public List<String> getAllUsers() throws RemoteException {
        String query = "SELECT username FROM users";
        List<String> users = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(query);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                users.add(rs.getString("username"));
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving users.");
            e.printStackTrace();
        }
        return users;
    }

    @Override
public void print(String filename, String printer, String sessionToken) throws RemoteException {
    System.out.println("entro al print");
    checkPermission(sessionToken, "print");
    System.out.println("Printing " + filename + " on " + printer);
}

@Override
public void queue(String printer, String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "queue");
    System.out.println("Listing queue for printer: " + printer);
}

@Override
public void topQueue(String printer, int job, String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "topQueue");
    System.out.println("Moving job " + job + " to the top of the queue for printer: " + printer);
}

@Override
public void start(String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "start");
    serverRunning = true;
    System.out.println("Print server started.");
}

@Override
public void stop(String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "stop");
    serverRunning = false;
    System.out.println("Print server stopped.");
}

@Override
public void restart(String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "restart");
    stop(sessionToken);
    start(sessionToken);
}


@Override
public void status(String printer, String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "status");
    System.out.println("Status of printer " + printer + ": Ready");
}

@Override
public void readConfig(String parameter, String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "readConfig");
    System.out.println("Config parameter " + parameter + ": value");
}

@Override
public void setConfig(String parameter, String value, String sessionToken) throws RemoteException {
    checkPermission(sessionToken, "setConfig");
    System.out.println("Setting config " + parameter + " to " + value);
}

}
