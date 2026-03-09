# Secure Resource Management API – FastAPI Security Testing using OWASP ISVS

![Python](https://img.shields.io/badge/Python-3.x-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![Security Testing](https://img.shields.io/badge/Security-Testing-red)
![OWASP ISVS](https://img.shields.io/badge/OWASP-ISVS-orange)
![GitHub Repo stars](https://img.shields.io/github/stars/Suraj-Tirumali/fastapi-security-testing-owasp-isvs?style=social)

FastAPI based backend API with automated security testing aligned with the **OWASP IoT Security Verification Standard (ISVS)**.

This project demonstrates authentication validation, authorization enforcement, password policy testing, brute-force attack simulation, and rate limiting verification for IoT resource management systems.

## Overview

This repository demonstrates the development and security testing of a backend API designed for managing users and IoT resources. The backend is built using **FastAPI** and **PostgreSQL**, and security testing was conducted based on the **OWASP IoT Security Verification Standard (ISVS)**.

The project focuses on validating authentication mechanisms, authorization controls, password management policies, and resource identity management within an IoT ecosystem.

This repository contains:

- FastAPI backend implementation
- Automated API security testing scripts
- OWASP ISVS control mapping
- Security testing documentation and reports

---

## Technologies Used

- Python
- FastAPI
- PostgreSQL
- JWT Authentication
- Postman
- Custom Python API testing scripts

---

## Testing Approach

Security testing was conducted using automated Python scripts that simulate real-world attack scenarios against the API endpoints.  

Tests were executed to validate authentication flows, access control mechanisms, password policies, and resource identity enforcement in accordance with OWASP ISVS guidelines.

## Project Structure

```
iot-api-security-testing-isvs
│
├── backend
│   ├── app
│   │   ├── manager.py
│   │   ├── database.py
│   │   ├── resource.py
│   │   ├── limiter_config.py
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── user.py
│   │   └── utils.py
│   │
│   ├── postman_client.py
│   ├── FastAPI.postman_collection.json
│   └── requirements.txt
│
├── security_tests
│   ├── authorization_test.py
│   ├── password_policy_test.py
│   ├── manager_password_change_test.py
│   ├── resource_identity_test.py
│   └── isvs_security_tests.py
│
├── documentation
│   ├── isvs_mapping.md
│   └── security_test_report.md
│
└── README.md
```

## Backend API

The backend provides core functionality required for managing users and IoT resources.

### Core Features

- User registration and authentication
- JWT-based authentication tokens
- Resource registration and management
- Administrative resource control
- Password management
- Resource ownership traceability

### API Routers

| Router | Description |
|------|-------------|
| `/user` | User authentication and password management |
| `/resource` | Resource registration and ownership validation |
| `/manager` | Administrative resource and user management |

FastAPI automatically generates interactive API documentation (Swagger UI) available at:

<http://localhost:8000/docs>

---

## Security Testing

Security testing was performed to validate the backend against common API security vulnerabilities.

The testing covered:

- Authentication validation
- Authorization enforcement
- Password policy enforcement
- Resource identity validation
- Brute-force attack simulation
- Rate limiting validation

Custom Python scripts were developed to automate these security test scenarios.

---

## OWASP ISVS Compliance

Security testing followed the **OWASP IoT Security Verification Standard (ISVS)**.

Testing focused on **Section 2.1 – User Space Application Requirements**.

### Implemented Controls

| ISVS Control | Description |
|--------------|-------------|
| 2.1.1 | Unique user identification |
| 2.1.2 | Unique resource identification |
| 2.1.3 | Strong authentication enforcement |
| 2.1.4 | Authentication framework validation |
| 2.1.5 | Password security validation |
| 2.1.6 | Secure password change |
| 2.1.7 | Password reuse prevention |
| 2.1.8 | Administrative password validation |
| 2.1.9 | Brute-force attack protection |
| 2.1.10 | Resource identity integrity |

Detailed mapping between test scripts and ISVS controls is available in:
`documentation/isvs_mapping.md`

---

## Security Test Report

A complete security testing report is available at:
`documentation/security_test_report.md`

The report includes:

- Test objectives
- Testing methodology
- Security test categories
- Brute-force attack simulation results
- Rate limiting validation
- Security assessment summary

---

## Example Security Tests

### Authentication Testing

- Valid login attempts
- Invalid credential attempts
- Accessing protected endpoints without authentication tokens

### Authorization Testing

- Unauthorized resource access attempts
- Cross-user data access validation

### Resource Identity Validation

- Duplicate resource registration tests
- Resource ownership validation

### Brute Force Simulation

Automated login attempts were executed using password lists to simulate credential brute-force attacks.

### Rate Limiting Validation

Multiple login attempts were generated within short intervals to verify rate limiting behavior on authentication endpoints.

---

## Running the Backend

Install dependencies:

```
pip install -r requirements.txt
```

Run the FastAPI server:

```
uvicorn app.main:app --reload
```


Once the server starts, access the interactive API documentation (Swagger UI) available at:

<http://localhost:8000/docs>

---

## Key Learning Outcomes

This project demonstrates practical experience with:

- Backend API development using FastAPI
- Security testing of REST APIs
- Authentication and authorization validation
- Brute force attack simulation
- Rate limiting implementation testing
- OWASP IoT Security Verification Standard (ISVS) compliance testing
- Automated API testing using Python scripts

---

## License

This project is intended for educational and demonstration purposes only.

## Author

**Suraj Tirumali**

This project was developed as a practical exploration of backend API security testing and OWASP IoT Security Verification Standard (ISVS) compliance.
