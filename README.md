# **Password Storage Project - Readme**

Our presentation powerpoint is available at this Canva : [link](https://www.canva.com/design/DAF_alkwDhA/NLhRPGnFNZsi2oA5ZoHIdA/edit?utm_content=DAF_alkwDhA&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton).

# Project Implementation

## Overview

In our upcoming session, we'll present the implementation for the password storage project. Building on our discussions of various attack scenarios and their solutions, we will analyze the robustness of our implementation, its potential weaknesses, and areas for improvement. The grade will reflect the security strength of the implemented system.

## Requirements

Our focus is on password storage, akin to an application with a user system where passwords must be stored securely. The application is executable, allowing for user registration and login through a terminal interface.

For cryptographic functions, the Google Tink library must be utilized, except for hash functions. Implementations using other libraries will not be considered.

## Architecture of Our Project

```json
.
├── docker-compose.yml
├── S1
│   ├── app.py
│   ├── cert.pem
│   └── Dockerfile
└── S2
    ├── cert.pem
    ├── Dockerfile
    ├── hsm.py
    ├── key.pem
    └── openssl.cnf
```


## Our User Interface Application (S1)

The user interface for registration and login is implemented in Python, leveraging the bcrypt library for secure password handling. The application communicates with the HSM for encryption and decryption tasks.

### Implementation Details

- S1's `app.py` script handles the user registration and login process.
- Passwords are hashed using bcrypt and then encrypted/decrypted via communication with S2, the HSM service.
- The communication between S1 and S2 is conducted over HTTPS for security and avoiding MiM attacks.

### Build and Run

We use Docker Compose for containerization:

```
docker-compose up --build
```

To interact with the application via a terminal:

```
docker attach project-crypto_app_1
```

## Our Hardware Security Module (HSM) Simulation (S2)

The HSM simulation is implemented using Flask and the Tink library to provide encryption services to S1.

### HSM Service Implementation

- S2's `hsm.py` script provides the encryption and decryption API endpoints.
- The Tink library is used to perform cryptographic operations.

### SSL Key and Certificate Generation

To create a self-signed SSL certificate for development purposes, we uslowing command:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout key.pem -out cert.pem -config openssl.cnf
```

### Interacting with the HSM Service

Run the Docker container and communicate via HTTPS requests for encryption and decryption.

## Security Considerations

It is crucial to ensure the communication between S1 and S2 is secure. Therefore, we implemented HTTPS and provided instructions on how to generate a self-signed SSL certificate.

We have also considered the following for our project's security:

- Implementing strong entropy for password hashing.
- Securely storing user credentials.
- Containerizing services to maintain isolated environments.

## How to Use

To run the project, ensure Docker and Docker Compose are installed and execute:

```
docker-compose up --build
```

To register or log in, use the appropriate commands when prompted in the terminal attached to the S1 container.

## Future Improvements

- Implement a user-friendly web interface for registration and login.
- Transition to CA-signed certificates for SSL/TLS encryption.
- Continuous security audits and updates to maintain strong defense against evolving threats.
