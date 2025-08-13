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
import java.util.List;
import java.util.Map;
import com.storage.server.TokenEncryption;

public class PasswordManagerImpl extends UnicastRemoteObject implements PasswordManager {
    private static final String DB_URL = "jdbc:sqlite:user_management.db";
    @SuppressWarnings("unused")
    private boolean serverRunning = false;
    private final long SESSION_TIMEOUT = 1 * 60 * 1000;
    private Map<String, Long> activeSessions = new HashMap<>();
    
    protected PasswordManagerImpl() throws RemoteException {
        super();
        initializeDatabase();
    }

    // Method to initialize the database and create the table if it does not exist
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

    // Method to connect to the database
    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }
    
    private boolean validateSession(String encryptedToken) throws RemoteException {
        String decryptedToken = TokenEncryption.decrypt(encryptedToken); // Decrypt to get original token
        Long expirationTime = activeSessions.get(encryptedToken);

        if (expirationTime == null) { // Session token not found
            throw new RemoteException("Session token not found. Please log in again.");
        }

        if (System.currentTimeMillis() > expirationTime) { // Checks if the token has expired
            activeSessions.remove(encryptedToken); // Removes expired token
            System.out.println("Session token expired: " + decryptedToken);
            throw new RemoteException("Session expired. Please log in again.");
        }

        // Token is valid, renew expiration time  
        activeSessions.put(encryptedToken, System.currentTimeMillis() + SESSION_TIMEOUT);
        return true;
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

    private String generateSecureSessionToken() { // GENERATE SESSION TOKEN
        SecureRandom secureRandom = new SecureRandom(); // Initializes a secure random number generator
        byte[] randomBytes = new byte[32]; // 256-bit token (32 bytes) (Creates a byte array)
        secureRandom.nextBytes(randomBytes); // Fills the byte array
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes); // Encodes the byte array into a Base64 string
    }
    
    @Override
    public boolean authenticateUser(String username, String plainPassword) throws RemoteException {
        String query = "SELECT password FROM users WHERE username = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String storedPassword = rs.getString("password");
                    return hashPassword(plainPassword).equals(storedPassword); // Compare hashed passwords
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
    
    @Override
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

            return rowsAffected > 0; // Returns true if the user was deleted
        } catch (SQLException e) {
            System.err.println("Error deleting user.");
            e.printStackTrace();
            return false;
        }
    }

    @Override // Log in
    public String login(String username, String password) throws RemoteException {
        if (authenticateUser(username, password)) { // If user is authenticated
            String sessionToken = generateSecureSessionToken(); // Generate a session token
            String encryptedToken = TokenEncryption.encrypt(sessionToken); // Encrypt token
            activeSessions.put(encryptedToken, System.currentTimeMillis() + SESSION_TIMEOUT); 
            System.out.println("Login successful. Session token (encrypted): " + encryptedToken);
            System.out.println("Session token (not encrypted): " + sessionToken);
            return encryptedToken;
        }
        return null;
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
    
    // PRINT SERVER
    @Override
    public void print(String filename, String printer, String sessionToken) throws RemoteException {
        System.out.println("These are the users in the database: " + getAllUsers());
        if (validateSession(sessionToken)) {
            System.out.println("Printing " + filename + " on " + printer);
        } else {
            throw new RemoteException("Session expired or invalid.");
        }
    }

    @Override
    public void queue(String printer, String sessionToken) throws RemoteException {
        if (validateSession(sessionToken)) {
            System.out.println("Listing queue for printer: " + printer);
        }
        // For demo, just a static message; in a real scenario, return the actual queue
        System.out.println("Current print jobs for " + printer + ": None"); // Placeholder
    }

    @Override
    public void topQueue(String printer, int job, String sessionToken) throws RemoteException {
        if (validateSession(sessionToken)) {
            System.out.println("Moving job " + job + " to the top of the queue for printer: " + printer);
        }
    }

    @Override
    public void start() throws RemoteException {
        serverRunning = true;
        System.out.println("Print server started.");
    }

    @Override
    public void stop() throws RemoteException {
        serverRunning = false;
        System.out.println("Print server stopped.");
    }

    @Override
    public void restart() throws RemoteException {
        stop();
        start();
    }

    @Override
    public void status(String printer, String sessionToken) throws RemoteException {
        // Simulate printing status
        if (validateSession(sessionToken)) {
            System.out.println("Status of printer " + printer + ": Ready");
        }
    }

    @Override
    public void readConfig(String parameter, String sessionToken) throws RemoteException {
        // Simulate reading a configuration parameter
        if (validateSession(sessionToken)) {
            System.out.println("Config parameter " + parameter + ": value");
        }
    }

    @Override
    public void setConfig(String parameter, String value, String sessionToken) throws RemoteException {
        // Simulate setting a configuration parameter
        if (validateSession(sessionToken)) {
            System.out.println("Setting config " + parameter + " to " + value);
        }
    }
}