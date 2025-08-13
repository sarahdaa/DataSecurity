package com.storage.server;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class PasswordManagerServer {
    public static void main(String[] args) {
        try {
            PasswordManager manager = new PasswordManagerImpl();
            Registry registry = LocateRegistry.createRegistry(1099);
            registry.rebind("PasswordManager", manager);
            System.out.println("Password Manager Server is running...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// ALL RUN FROM demo/src/main/java

// COMPILE: javac com/storage/client/*.java com/storage/server/*.java

// SERVER: java -classpath ".:sqlite-jdbc-3.47.0.0.jar" -Djava.rmi.server.hostname=localhost com.storage.server.PasswordManagerServer

// CLIENT: java -cp ".:sqlite-jdbc-3.47.0.0.jar" com.storage.client.PrintClient