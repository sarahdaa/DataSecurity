package com.storage.client;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import com.storage.server.PasswordManager;

public class PasswordManagerClient {
    public static void main(String[] args) {
        try {
            // Connect to the RMI registry and look up the PasswordManager service
            Registry registry = LocateRegistry.getRegistry("localhost", 1099);
            PasswordManager manager = (PasswordManager) registry.lookup("PasswordManager");

            // Check if the database is empty and clear it if it is not
            if (!manager.isDatabaseEmpty()) {
                System.out.println("The database is not empty. Proceeding to clear it...");
                manager.clearUsers();
            } else {
                System.out.println("The database is already empty.");
            }

            // List of test users
            String[] usernames = {"testUser1", "testUser2", "testUser3"};
            String initialPassword = "password123";
            String newPassword = "newPassword456";

            // Create multiple users
            System.out.println("=== Creating Users ===");
            for (String username : usernames) {
                try {
                    boolean isAdded = manager.addUser(username, initialPassword);
                    System.out.println("User " + username + " created: " + (isAdded ? "Success" : "Failed"));
                } catch (Exception e) {
                    System.out.println("Error creating user " + username + ": " + e.getMessage());
                }
            }

            // Change password for each user
            System.out.println("\n=== Changing Passwords ===");
            for (String username : usernames) {
                try {
                    boolean isPasswordChanged = manager.updatePassword(username, initialPassword, newPassword);
                    System.out.println("Password change for " + username + ": " + (isPasswordChanged ? "Success" : "Failed"));
                } catch (Exception e) {
                    System.out.println("Error changing password for " + username + ": " + e.getMessage());
                }
            }

            // Final verification: confirm that users exist with the new password
            System.out.println("\n=== Final Verification: Users Present in Database ===");
            for (String username : usernames) {
                try {
                    boolean isAuthenticated = manager.authenticateUser(username, newPassword);
                    System.out.println("User " + username + " authenticated with the new password: " + (isAuthenticated ? "Success" : "Failed"));
                } catch (Exception e) {
                    System.out.println("Error authenticating user " + username + ": " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.out.println("Error connecting to or interacting with the RMI service: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
