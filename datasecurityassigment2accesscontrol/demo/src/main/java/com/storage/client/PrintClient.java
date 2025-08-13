package com.storage.client;
import com.storage.server.PasswordManager;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

public class PrintClient {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String host = "localhost"; // or server IP
        String sessionToken = null; //initialize session token

        try {
            Registry registry = LocateRegistry.getRegistry("localhost", 1101);
            PasswordManager printServer = (PasswordManager) registry.lookup("PasswordManager");

            while(true){
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                System.out.print("Enter password: ");
                String password = scanner.nextLine();

                
                System.out.println("Debug: Attempting to log in with username: " + username);
                sessionToken = printServer.login(username, password); //get sessionToken from server


                if (sessionToken == null) { // login failed
                    System.out.println("Login failed. Please check your credentials.");
                    return;
                    }
                System.out.println("Login successful. Session token: " + sessionToken); //login successfull
            
                while (true) {
                    System.out.println("\nChoose an action: print, queue, status, or logout");
                    String action = scanner.nextLine();

                    try{ 
                        switch (action) {
                            case "print":
                                printServer.print("document.txt", "Printer1", sessionToken);
                                System.out.println("Print method completed.");
                                break;
                            case "queue":
                                printServer.queue("Printer1", sessionToken);
                                System.out.println("Queue method completed.");
                                break;
                            case "status":
                                printServer.status("Printer1", sessionToken);
                                System.out.println("Status method completed.");
                                break;
                            case "stop":
                                printServer.stop(sessionToken);
                                System.out.println("Stop method completed.");
                                break;
                            case "restart":
                                printServer.restart(sessionToken);
                                System.out.println("Restart method completed.");
                                break;
                            case "topQueue":
                                printServer.topQueue("Printer1", 0, sessionToken);
                                System.out.println("topQueue method completed.");
                                break;
                            case "readConfig":
                                printServer.readConfig("Printer1", sessionToken);
                                System.out.println("topQueue method completed.");
                                break;
                            case "setConfig":
                                printServer.setConfig("Printer1", "Printer1", sessionToken);
                                System.out.println("topQueue method completed.");
                                break;
                            case "logout":
                                printServer.logout(sessionToken);
                                System.out.println("Logged out successfully.");
                                sessionToken = null; // sets token to null --> log out = end session

                                break;
                            default:
                                System.out.println("Invalid action. Please try again.");
                                break;
                        }
                        if (action.equals("logout")) {

                            break; // exit inner loop if user logout

                        }
                    }
                    catch (RemoteException e) {
                        System.out.println("Action could not be completed: " + e.getMessage());
                        if (e.getMessage().contains("Access denied")) {
                            System.out.println("Unauthorized access. Please choose another action.");
                        } else {
                            System.out.println("Session expired or invalid. Please log in again.");
                            break;
                        }
                    }
                }
                if (sessionToken == null) {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}