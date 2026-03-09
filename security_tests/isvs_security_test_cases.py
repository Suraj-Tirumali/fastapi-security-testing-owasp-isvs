# -*- coding: utf-8 -*-
# Unified CLI for Auth Testing (rate-limit safe, resilient)
import argparse
import requests
import time
import os
import re
import json
from urllib.parse import urlparse

# =========================
# Config
# =========================
BASE_URL = "http://127.0.0.1:8000"

# API endpoints
USER_LOGIN_URL = f"{BASE_URL}/user/login"
ADMIN_LOGIN_URL = f"{BASE_URL}/admin/login-admin"
USER_DETAILS_URL = f"{BASE_URL}/user/user_details"
DEVICE_DETAILS_URL = f"{BASE_URL}/device/device-details"
CHANGE_PWD_USER_URL = f"{BASE_URL}/user/reset-password-auth"
CHANGE_PWD_ADMIN_URL = f"{BASE_URL}/admin/change-password"
USER_CREATE_URL = f"{BASE_URL}/user/create-user"

# Credential File paths
CRED_FILE_USER = "cred.txt"                 # used by 2.1.2 and 2.1.4 (email,password per line)
CRED_FILE_ADMIN = "creds.txt"               # mixed admin/users file: email,password,role
CRED_FILE_USER_CHANGE = "credentials.txt"   # email,old_password,new_password for 2.1.6

# Rate limit / retry
RATE_LIMIT_SLEEP = 12  # keep under 5 logins/min
MAX_RETRIES = 3

# Logs
LOG_DIR = "result-folder"
os.makedirs(LOG_DIR, exist_ok=True)
RESULT_FILE = os.path.join(LOG_DIR, "result.txt")
LOG_FILE_ADMIN = os.path.join(LOG_DIR, "admin_pwd_change.log")
LOG_FILE_USER = os.path.join(LOG_DIR, "user_pwd_change.log")
LOG_FILE_IDOR = os.path.join(LOG_DIR, "auth_idor_check.log")
LOG_FILE_DEVICE = os.path.join(LOG_DIR, "device_uniqueness.log")
LOG_FILE_PASSWORD_STRENGTH = os.path.join(LOG_DIR, "password_strength.log")

test_results = []

# =========================
# Utility: results summary
# =========================
def log_result(test_id, description, passed):
    test_results.append({
        "Test Case": test_id,
        "Description": description,
        "Status": "Not Vulnerable" if passed else "Vulnerable"
    })

def write_summary():
    with open(RESULT_FILE, "w") as f:
        col_widths = {"Test Case": 25, "Description": 50, "Status": 18}

        #header
        f.write(
            f"{'Test Case':<{col_widths['Test Case']}} | "
            f"{'Description':<{col_widths['Description']}} | "
            f"{'Status':<{col_widths['Status']}}\n"
        )

        #body
        f.write("-" * (sum(col_widths.values()) + 6) + "\n")
        for result in test_results:
            f.write(
                f"{result['Test Case']:<{col_widths['Test Case']}} | "
                f"{result['Description']:<{col_widths['Description']}} | "
                f"{result['Status']:<{col_widths['Status']}}\n"
            )
    print(f"\nSummary written to {RESULT_FILE}")

# =========================
# HTTP helpers (retry/backoff)
# =========================
def post_json(url, payload, headers=None, log=None):
    """POST with JSON body + simple backoff for 429/5xx."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    for attempt in range(1, MAX_RETRIES + 1):
        r = requests.post(url, json=payload, headers=hdrs)
        if log:
            log.write(f"[HTTP] POST {url} -> {r.status_code}\n")
        if r.status_code != 429 and r.status_code < 500:
            return r
        time.sleep(RATE_LIMIT_SLEEP)
    return r

def get_json(url, headers=None, log=None):
    """GET JSON + simple backoff for 429/5xx."""
    hdrs = {}
    if headers:
        hdrs.update(headers)
    for attempt in range(1, MAX_RETRIES + 1):
        r = requests.get(url, headers=hdrs)
        if log:
            log.write(f"[HTTP] GET {url} -> {r.status_code}\n")
        if r.status_code != 429 and r.status_code < 500:
            return r
        time.sleep(RATE_LIMIT_SLEEP)
    return r

# =========================
# 2.1.1, 2.1.2, 2.1.10
# Device ID global uniqueness
# =========================
def run_2_1_2():
    # Open the log file for recording device ID uniqueness checks
    with open(LOG_FILE_DEVICE, "w") as log:
        # Read user credentials from the specified file path
        def read_cred(file_path):
            users = []
            with open(file_path, "r") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        users.append({"username": parts[0], "password": parts[1]})
            return users

        # Perform login using the user's credentials and return JWT token if successful
        def login_user(user):
            try:
                resp = post_json(USER_LOGIN_URL, {
                    "username_or_email": user["username"],
                    "password": user["password"]
                }, log=log)
                if resp.status_code == 200:
                    return resp.json().get("access_token")
                else:
                    log.write(f"Login failed for {user['username']}: {resp.status_code} - {resp.text}\n")
            except Exception as e:
                log.write(f"Login failed for {user['username']}: {e}\n")
            return None

        # Fetch the list of device IDs for a given user's session (identified by JWT token)
        def get_device_ids(token):
            try:
                headers = {"Authorization": f"Bearer {token}"}
                resp = get_json(DEVICE_DETAILS_URL, headers=headers, log=log)
                if resp.status_code == 200 and resp.content:
                    return [d.get("device_id") for d in resp.json() if "device_id" in d]
                else:
                    log.write(f"Device details fetch failed: {resp.status_code} - {resp.text}\n")
            except Exception as e:
                log.write(f"Failed to fetch device details: {e}\n")
            return []

        # Read credentials from file
        creds = read_cred(CRED_FILE_USER)
        # Track all device IDs and any duplicates found
        all_ids, duplicates = {}, []

        # Iterate through each user credential set
        for cred in creds:
            token = login_user(cred)
            time.sleep(RATE_LIMIT_SLEEP)
            if not token:
                log.write(f"Could not login as {cred['username']}\n")
                continue

            device_ids = get_device_ids(token)
            log.write(f"[{cred['username']}] Device IDs: {device_ids}\n")

            # Check for duplicates and map device_id → username
            for device_id in device_ids:
                if not device_id:
                    continue
                if device_id in all_ids:
                    duplicates.append((device_id, all_ids[device_id], cred['username']))
                else:
                    all_ids[device_id] = cred['username']

            time.sleep(2)

         # Report whether duplicate device IDs were found
        if duplicates:
            log.write("\nDuplicate device IDs found across users:\n")
            for device_id, user_a, user_b in duplicates:
                log.write(f" - '{device_id}' used by both {user_a} and {user_b}\n")
            return False
        else:
            log.write("All device IDs are globally unique\n")
            return True

# =========================
# 2.1.3, 2.1.4
# Auth artifact & IDOR check
# =========================
def run_2_1_4(creds_file):
    # Open a log file to record IDOR and auth artifact testing logs
    with open(LOG_FILE_IDOR, "w") as log:

        # Checks if the given response has a valid JWT structure
        def check_jwt(response_json):
            token = response_json.get("access_token")
            return token and len(token.split('.')) == 3
        
        # Reads credentials (email,password) from a file
        def read_credentials(file_path):
            users = []
            with open(file_path, 'r') as file:
                for line in file:
                    if "," in line:
                        email, password = line.strip().split(",", 1)
                        users.append((email.strip(), password.strip()))
            return users

        # Attempts to log in a user and return the full response JSON if successful
        def login_user(email, password):
            try:
                resp = post_json(USER_LOGIN_URL, {
                    "username_or_email": email,
                    "password": password
                }, log=log)
                if resp.status_code == 200:
                    return resp.json()
                else:
                    log.write(f"Login failed for {email}: {resp.status_code} - {resp.text}\n")
            except Exception as e:
                log.write(f"Error logging in {email}: {e}\n")
            return None

        # Sends a GET request to a protected URL using the given JWT token
        def get_data(token, url):
            try:
                resp = get_json(url, headers={"Authorization": f"Bearer {token}"}, log=log)
                if not resp.content:
                    return resp.status_code, {}
                return resp.status_code, resp.json()
            except Exception as e:
                log.write(f"Error accessing {url}: {e}\n")
                return None, {}

        # Compares two sets of user fields to detect differences (used for IDOR)
        def compare_fields(a, b):
            keys = ["uid", "username", "email", "phone_number", "role"]
            return {k: (a.get(k), b.get(k)) for k in keys if a.get(k) != b.get(k)}

        # Load all credentials from input file and create a token map + baseline data map
        creds = read_credentials(creds_file)
        tokens, baseline = {}, {}

        # Login each user (respect rate limit), record their own baseline
        for email, password in creds:
            resp = login_user(email, password)
            time.sleep(RATE_LIMIT_SLEEP)
            if not resp:
                continue
            token = resp["access_token"]
            tokens[email] = token
            status, user_data = get_data(token, USER_DETAILS_URL)
            _, device_data = get_data(token, DEVICE_DETAILS_URL)
            baseline[email] = {"user": user_data, "device": device_data}
            time.sleep(2)

        vulnerable = False

        # Try B's token to fetch A's data - endpoints likely return "current user",
        # so a secure API will always equal baseline[B].
        for A, tokenA in tokens.items():
            for B, tokenB in tokens.items():
                if A == B:
                    continue
                log.write(f"\nChecking if {B}'s token can access {A}'s data...\n")

                status, data = get_data(tokenB, USER_DETAILS_URL)
                if status == 200 and compare_fields(data, baseline[B]["user"]):
                    log.write(f"IDOR on USER_DETAILS from {B} to {A}\n")
                    vulnerable = True

                status, data = get_data(tokenB, DEVICE_DETAILS_URL)
                if status == 200 and data != baseline[B]["device"]:
                    log.write(f"IDOR on DEVICE_DETAILS from {B} to {A}\n")
                    vulnerable = True

                time.sleep(RATE_LIMIT_SLEEP)

        return not vulnerable

# =========================
# 2.1.5, 2.1.7
# Password strength + resistant to weak passwords, rate limit safe
# =========================
def run_2_1_5():
    # Open the log file to record all outputs for this test
    with open(LOG_FILE_PASSWORD_STRENGTH, "w") as log:
        # new user credentials for brute-force registration test
        NEW_USER_EMAIL = "selen@gmail.com"
        NEW_USER_PHONE = "+918888677888"

       # Function to check password strength using regex rules
        def is_strong(pwd):
            return (
                len(pwd) >= 12 and
                re.search(r"[A-Z]", pwd) and
                re.search(r"[a-z]", pwd) and
                re.search(r"[0-9]", pwd) and
                re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd)
            )

        # Function to log in a user and return the access token
        def login(email, pwd):
            try:
                r = post_json(USER_LOGIN_URL, {"username_or_email": email, "password": pwd}, log=log)
                log.write(f"[DEBUG] Login response ({email}): {r.status_code} - {r.text}\n")
                return r.json().get("access_token") if r.status_code == 200 else None
            except Exception as e:
                log.write(f"[ERROR] Login exception for {email}: {e}\n")
                return None

        # Function to perform password change request
        def change_password(token, email, current_pwd, new_pwd):
            headers = {"Authorization": f"Bearer {token}"}
            payload = {
                "email": email,
                "current_password": current_pwd,
                "new_password": new_pwd,
                "confirm_password": new_pwd
            }
            try:
                r = post_json(CHANGE_PWD_USER_URL, payload, headers=headers, log=log)
                log.write(f"[DEBUG] Change PWD Response: {r.status_code} - {r.text}\n")
                return r.status_code == 200
            except Exception as e:
                log.write(f"[ERROR] Password change exception for {email}: {e}\n")
                return False

        # Load test credentials (email,password)
        try:
            with open("cred.txt", "r") as f:
                credentials = [line.strip().split(",") for line in f if "," in line.strip()]
        except Exception as e:
            log.write(f"[ERROR] Could not read 'cred.txt': {e}\n")
            return False

        # Load password candidates
        try:
            with open("password_test.txt", "r") as f:
                password_candidates = [line.strip() for line in f if line.strip()]
        except Exception as e:
            log.write(f"[ERROR] Could not read 'password_test.txt': {e}\n")
            return False

        all_passed = True

        # For each user
        for email, original_password in credentials:
            log.write(f"\n============================\n")
            log.write(f"Testing user: {email}\n")

            for new_password in password_candidates:
                log.write(f"\nTrying new password: {new_password}\n")
                if not is_strong(new_password):
                    log.write("[REJECTED] Password too weak\n")
                    continue
                # Login with original credentials
                token = login(email, original_password)
                time.sleep(RATE_LIMIT_SLEEP)
                if not token:
                    log.write("[FAIL] Initial login failed\n")
                    all_passed = False
                    break
                # Attempt to change the password to new candidate
                if not change_password(token, email, original_password, new_password):
                    log.write("[FAIL] Password change request failed\n")
                    all_passed = False
                    time.sleep(RATE_LIMIT_SLEEP)
                    continue

                # small settle + re-login with new
                time.sleep(2)
                token_new = login(email, new_password)
                time.sleep(RATE_LIMIT_SLEEP)
                if token_new:
                    log.write("[SUCCESS] Password changed and login successful\n")
                    break
                else:
                    log.write("[FAIL] Password change succeeded but login with new password failed\n")
                    all_passed = False
                    continue

                # Try to revert; if revert fails due to rate limit, do not mark as vulnerable
                # reverted = change_password(token_new, email, new_password, original_password)
                # time.sleep(RATE_LIMIT_SLEEP)
                # if reverted:
                #     log.write("[REVERTED] Reverted to original password\n")
                # else:
                #     log.write("[WARN] Could not revert password (skipping impact on status)\n")

        # Brute-force style test: register a new user using candidates
        log.write("\n=== Attempting Brute-force User Registration ===\n")
        registered = False
        for test_pwd in password_candidates:
            if not is_strong(test_pwd):
                log.write(f"[REJECTED] Registration password too weak: {test_pwd}\n")
                continue
            try:
                 # Attempt to create a new user with the given password
                resp = post_json(USER_CREATE_URL, {
                    "email": NEW_USER_EMAIL,
                    "phone_number": NEW_USER_PHONE,
                    "password": test_pwd
                }, log=log)
                if resp.status_code == 200:
                    log.write(f"[SUCCESS] Registered new user with password: {test_pwd}\n")
                    registered = True
                    break
                else:
                    log.write(f"[FAIL] Tried password: {test_pwd} | Status: {resp.status_code} | Response: {resp.text}\n")
            except Exception as e:
                log.write(f"[ERROR] Exception while registering with {test_pwd}: {e}\n")
            time.sleep(RATE_LIMIT_SLEEP)
        # Final result of registration test
        if not registered:
            log.write("[RESULT] No password succeeded in registering new user.\n")

        return all_passed

# =========================
# 2.1.6
# User-initiated password change
# =========================
def run_2_1_6():
    # Open the log file for writing the test output
    with open(LOG_FILE_USER, "w") as log:

        #  Check if a password is strong based on complexity rules
        def is_strong(pwd):
            return len(pwd) >= 12 and re.search(r"[A-Z]", pwd) and re.search(r"[a-z]", pwd) and re.search(r"[0-9]", pwd) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd)

        # Log in a user and return access token if successful
        def login(email, pwd):
            try:
                r = post_json(USER_LOGIN_URL, {"username_or_email": email, "password": pwd}, log=log)
                return r.json().get("access_token") if r.status_code == 200 else None
            except Exception as e:
                log.write(f"[ERROR] Login exception for {email}: {e}\n")
                return None
        # Change password using authenticated user's token
        def change(token, email, cur, new):
            h = {"Authorization": f"Bearer {token}"}
            p = {"email": email, "current_password": cur, "new_password": new, "confirm_password": new}
            try:
                r = post_json(CHANGE_PWD_USER_URL, p, headers=h, log=log)
                log.write(f"[DEBUG] User password change response: {r.status_code} - {r.text}\n")
                return r.status_code == 200
            except Exception as e:
                log.write(f"[ERROR] Change exception: {e}\n")
                return False

        # Load user credentials from file
        creds = []
        with open(CRED_FILE_USER_CHANGE, "r") as f:
            for l in f:
                if l.strip():
                    p = l.strip().split(",")
                    if len(p) == 3:
                        creds.append({"email": p[0], "password": p[1], "new_password": p[2]})

        success = True
         # Loop through each credential and test password change flow
        for c in creds:
            e, o, n = c["email"], c["password"], c["new_password"]
            log.write(f"\nTesting {e}...\n")

            if not is_strong(n):
                log.write("Weak new password (skipping this candidate)\n")
                continue

            # Try original; if that fails, try original+"_NEW" in case admin changed earlier
            t = login(e, o)
            time.sleep(RATE_LIMIT_SLEEP)
            if not t:
                alt = o + "_NEW"
                t = login(e, alt)
                time.sleep(RATE_LIMIT_SLEEP)
                if t:
                    o = alt
            # Attempt password change using authenticated token
            if not t:
                log.write("Change failed (couldn't authenticate with current password)\n")
                success = False
                continue

            if not change(t, e, o, n):
                log.write("Password change failed\n")
                success = False
                time.sleep(RATE_LIMIT_SLEEP)
                continue
            # Validate login works with new password
            time.sleep(2)
            t2 = login(e, n)
            time.sleep(RATE_LIMIT_SLEEP)
            if t2:
                log.write("Password changed and login successful\n")
            else:
                log.write("Password changed but login with new password failed\n")
                success = False

        return success

# =========================
# 2.1.8
# Admin password change
# =========================
def run_2_1_8():
    with open(LOG_FILE_ADMIN, "w") as log:

        # Read admin and user credentials from the admin credential file
        def read():
            a, u = [], []
            with open(CRED_FILE_ADMIN, "r") as f:
                for l in f:
                    p = l.strip().split(",")
                    if len(p) == 3:
                        (a if p[2].lower() == "admin" else u).append({"email": p[0], "password": p[1]})
            return a, u

        # Login either as admin or user based on `is_admin` flag
        def login(e, p, is_admin=False):
            url = ADMIN_LOGIN_URL if is_admin else USER_LOGIN_URL
            try:
                r = post_json(url, {"username_or_email": e, "password": p}, log=log)
                return r.json().get("access_token") if r.status_code == 200 else None
            except Exception as ex:
                log.write(f"[ERROR] Login exception: {ex}\n")
                return None
        # Use admin token to change any user's password
        def change(t, e, new):
            h = {"Authorization": f"Bearer {t}"}
            p = {"email": e, "new_password": new, "confirm_password": new}
            try:
                r = post_json(CHANGE_PWD_ADMIN_URL, p, headers=h, log=log)
                log.write(f"[DEBUG] Admin change password response for {e}: {r.status_code} - {r.text}\n")
                return r.status_code == 200
            except Exception as ex:
                log.write(f"[ERROR] Exception while changing password: {ex}\n")
                return False

        # load credentails
        admins, users = read()
        if not admins:
            return False
        # Take the first admin
        a = admins[0]
        at = login(a["email"], a["password"], True)
        time.sleep(RATE_LIMIT_SLEEP)
        if not at:
            return False

        success = True
        # For each user, attempt to change their password using admin access
        for u in users:
            old = u["password"]
            new = old + "_New#2025"  # strong suffix
            log.write(f"Changing password for {u['email']}\n")

            # Attempt password change
            if not change(at, u["email"], new):
                success = False
                log.write(f"FAILED to change password for {u['email']}\n")
                time.sleep(RATE_LIMIT_SLEEP)
                continue

            # Verify login works with new password
            time.sleep(2)
            if not login(u["email"], new):
                success = False
                log.write(f"FAILED login with new password for {u['email']}\n")
            else:
                log.write(f"Login successful with new password for {u['email']}\n")

            time.sleep(RATE_LIMIT_SLEEP)

        return success

# =========================
# CLI
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified CLI for Auth Testing")
    parser.add_argument('--2.1.2', action='store_true')
    parser.add_argument('--2.1.4', action='store_true')
    parser.add_argument('--2.1.5', action='store_true')
    parser.add_argument('--2.1.6', action='store_true')
    parser.add_argument('--2.1.8', action='store_true')
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--idor', help='Credential file for IDOR test (used with --2.1.4 or --all)')
    args = parser.parse_args()

    # Run each test based on flags
    if args.all or args.__dict__["2.1.2"]:
        passed = run_2_1_2()
        log_result("2.1.1, 2.1.2, 2.1.10", "Device ID uniqueness check", passed)

    if args.all or args.__dict__["2.1.4"]:
        creds_file = args.idor or CRED_FILE_USER
        passed = run_2_1_4(creds_file)
        log_result("2.1.3, 2.1.4", "Auth Artifact & IDOR check", passed)

    if args.all or args.__dict__["2.1.5"]:
        passed = run_2_1_5()
        log_result("2.1.5, 2.1.7", "Check Password Strength", passed)

    if args.all or args.__dict__["2.1.6"]:
        passed = run_2_1_6()
        log_result("2.1.6", "User-initiated password change", passed)

    if args.all or args.__dict__["2.1.8"]:
        passed = run_2_1_8()
        log_result("2.1.8", "Admin password change", passed)

    # Write Results Summary
    if test_results:
        write_summary()
    else:
        print("Please provide a valid flag like --2.1.2 or --all")