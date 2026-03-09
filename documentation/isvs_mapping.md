# OWASP ISVS Security Control Mapping

This document maps the implemented security tests in this project to the
requirements defined in the OWASP IoT Security Verification Standard (ISVS).

Reference:
https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS

Testing focused primarily on:

Section 2.1 – User Space Application Requirements

These tests were implemented during the development of a FastAPI-based backend
for an IoT resource management platform.

---

## Implemented Controls

### 2.1.1 Unique User Identification

Objective:
Ensure that every user account is uniquely identifiable within the system.

Test Implementation:
- User creation endpoints enforce unique usernames and emails.
- Duplicate account creation attempts are rejected.

Test Script:
authorization_test.py

---

### 2.1.2 Unique Resource Identification

Objective:
Ensure that each IoT resource is uniquely identifiable within the ecosystem.

Test Implementation:
- Attempt to register duplicate resource IDs across multiple users.
- Verify that duplicate resource registrations are rejected.

Test Script:
device_identity_test.py

---

### 2.1.3 Strong Authentication Enforcement

Objective:
Ensure that users must authenticate using valid credentials.

Test Implementation:
- Login validation tests using valid and invalid credentials.
- Authentication token validation.

Test Script:
authorization_test.py

---

### 2.1.4 Centralized Authentication Framework

Objective:
Ensure authentication is centrally managed and enforced consistently.

Test Implementation:
- Verify that protected endpoints require valid JWT tokens.
- Unauthorized requests should be rejected.

Test Script:
authorization_test.py

---

### 2.1.5 Password Security Enforcement

Objective:
Ensure password security policies are enforced.

Test Implementation:
- Password strength validation.
- Prevention of weak passwords during account creation.

Test Script:
password_policy_test.py

---

### 2.1.6 Secure Password Change Mechanism

Objective:
Ensure users can securely change their passwords.

Test Implementation:
- Password change API requires authentication.
- Current password verification enforced.

Test Script:
password_policy_test.py

---

### 2.1.7 Password Reuse Prevention

Objective:
Prevent reuse of previously used passwords.

Test Implementation:
- Attempt to reuse previous passwords.
- System rejects duplicate password submissions.

Test Script:
password_policy_test.py

---

### 2.1.8 Administrative Password Validation

Objective:
Ensure administrators follow the same secure password policies.

Test Implementation:
- Manager password change validation.
- Authentication enforcement for administrative actions.

Test Script:
manager_password_change_test.py

---

### 2.1.9 Brute Force Attack Protection

Objective:
Prevent unlimited login attempts.

Test Implementation:
- Automated login attempts using password lists.
- Validation of rate limiting behavior.

Test Script:
bruteforce_login_test.py

---

### 2.1.10 Resource Identity Integrity

Objective:
Ensure resource ownership and identity integrity.

Test Implementation:
- Validate resource ownership access control.
- Prevent unauthorized resource access.

Test Script:
resource_identity_test.py

---

## Not Implemented

### 2.1.11

This control was not implemented due to project timeline constraints during
the internship development phase.

---

## Summary

The implemented tests validate core security properties including:

- Authentication enforcement
- Authorization validation
- Password policy enforcement
- Resource identity verification
- Brute-force attack resistance
- Rate limiting validation

These tests help ensure the backend API follows security best practices
for IoT resource management systems.
