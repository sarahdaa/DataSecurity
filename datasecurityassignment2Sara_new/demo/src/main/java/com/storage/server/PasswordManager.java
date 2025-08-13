package com.storage.server;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface PasswordManager extends Remote {
    boolean addUser(String username, String password) throws RemoteException;
    boolean deleteUser(String username) throws RemoteException;
    boolean authenticateUser(String username, String password) throws RemoteException;
    boolean updatePassword(String username, String oldPassword, String newPassword) throws RemoteException;
    boolean isDatabaseEmpty() throws RemoteException;
    void clearUsers() throws RemoteException;
    List<String> getAllUsers() throws RemoteException;

    // SESSION MANAGEMENT
    String login(String username, String password) throws RemoteException;
    void logout(String sessionToken) throws RemoteException;

    // PRINT SERVER
    void print(String filename, String printer, String sessionToken) throws RemoteException;
    void queue(String printer, String sessionToken) throws RemoteException;
    void topQueue(String printer, int job, String sessionToken) throws RemoteException;
    void start() throws RemoteException;
    void stop() throws RemoteException;
    void restart() throws RemoteException;
    void status(String printer, String sessionToken) throws RemoteException;
    void readConfig(String parameter, String sessionToken) throws RemoteException;
    void setConfig(String parameter, String value, String sessionToken) throws RemoteException;
}


// ALL RUN FROM demo/src/main/java

//COMPILE: javac com/storage/client/*.java com/storage/server/*.java

// SERVER: java -classpath ".:sqlite-jdbc-3.47.0.0.jar" -Djava.rmi.server.hostname=localhost com.storage.server.PasswordManagerServer

// CLIENT: java -cp ".:sqlite-jdbc-3.47.0.0.jar" com.storage.client.PrintClient