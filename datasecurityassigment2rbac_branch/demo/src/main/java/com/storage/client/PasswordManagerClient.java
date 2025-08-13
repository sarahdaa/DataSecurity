package com.storage.client;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import com.storage.server.PasswordManager;

public class PasswordManagerClient {
    public static void main(String[] args) {
        try {
            
            Registry registry = LocateRegistry.getRegistry("localhost", 1101);
            PasswordManager manager = (PasswordManager) registry.lookup("PasswordManager");

            if (!manager.isDatabaseEmpty()) {
                System.out.println("The database is not empty. Proceeding to clear it...");
                manager.clearUsers();
            } else {
                System.out.println("The database is already empty.");
            }

            String[] usernames = {"Alice", "Bob", "Cecilia", "Erica", "David","Fred","George"};
            String initialPassword = "password123";
            String newPassword = "newPassword456";

            System.out.println("=== Creating Users ===");
            for (String username : usernames) {
                try {
                    boolean isAdded = manager.addUser(username, initialPassword);
                    System.out.println("User " + username + " created: " + (isAdded ? "Success" : "Failed"));
                } catch (Exception e) {
                    System.out.println("Error creating user " + username + ": " + e.getMessage());
                }
            }

            System.out.println("\n=== Changing Passwords ===");
            for (String username : usernames) {
                try {
                    boolean isPasswordChanged = manager.updatePassword(username, initialPassword, newPassword);
                    System.out.println("Password change for " + username + ": " + (isPasswordChanged ? "Success" : "Failed"));
                } catch (Exception e) {
                    System.out.println("Error changing password for " + username + ": " + e.getMessage());
                }
            }


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
