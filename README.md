# Data Security
## Overview
This project implements a client-server based password manager in Java, focusing on secure authentication and access control. The system uses session tokens and demonstrates both ACL (Access Control List) and RBAC (Role-Based Access Control) models. The project is a part of the course Data Security at DTU. Detailed information and reflections are given in "assingment2.pdf".

## Project Structure
- `datasecurityassigment2Sara_new`: **Authentication** – handles user login, password hashing, and session tokens.
- `datasecurityassigment2accesscontrol`: **Access Control with ACL** – manages permissions tied to individual users.
- `datasecurityassigment2rbac_branch`: **Access Control with RBAC** – permissions based on roles assigned to users.

## Technologies Used
- Java
- Java RMI (Remote Method Invocation)
- SQLite (user database)
- AES-256 (encryption)
- SHA-256 (password hashing)
