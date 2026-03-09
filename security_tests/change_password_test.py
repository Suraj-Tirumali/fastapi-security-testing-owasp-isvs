import requests
import re

BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = f"{BASE_URL}/user/login"
CHANGE_PWD_URL = f"{BASE_URL}/user/reset-password-auth"
CRED_FILE = "credentials.txt"
LOG_FILE = "changed_pwd.log"

def is_strong_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def read_credentials(file_path):
    creds = []
    with open(file_path, "r") as f:
        for line in f:
            if line.strip():
                parts = line.strip().split(',')
                if len(parts) == 3:
                    creds.append({
                        "email": parts[0],
                        "password": parts[1],
                        "new_password": parts[2]
                    })
    return creds

def login(email, password):
    payload = {"username_or_email": email, "password": password}
    try:
        resp = requests.post(LOGIN_URL, json=payload)
        if resp.status_code == 200:
            return resp.json().get("access_token")
    except Exception as e:
        print(f"Login error for {email}: {e}")
    return None

def change_password(token, email, current_pwd, new_pwd):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "email": email,
        "current_password": current_pwd,
        "new_password": new_pwd,
        "confirm_password": new_pwd
    }
    try:
        resp = requests.post(CHANGE_PWD_URL, json=payload, headers=headers)
        return resp.status_code == 200
    except Exception as e:
        print(f"Error changing password for {email}: {e}")
        return False

def store_log(email, old_pwd, new_pwd, reverted):
    with open(LOG_FILE, "a") as log:
        log.write(f"Email: {email} | Old Password: {old_pwd} | New Password: {new_pwd} | Reverted: {reverted}\n")

def main():
    creds = read_credentials(CRED_FILE)
    print(f"Loaded {len(creds)} credentials\n")

    for cred in creds:
        email = cred["email"]
        current_pwd = cred["password"]
        new_pwd = cred["new_password"]

        print(f"\nTesting password change for: {email}")

        if not is_strong_password(new_pwd):
            print(f"New password for {email} is not strong enough.")
            store_log(email, current_pwd, new_pwd, False)
            continue
        
        token = login(email, current_pwd)
        if not token:
            print(f"Login failed for {email}")
            continue

        success = change_password(token, email, current_pwd, new_pwd)
        if success:
            print(f"Password changed successfully for {email}")

            token_new = login(email, new_pwd)
            if token_new:
                print(f"Login successful with new password for {email}")

                reverted = change_password(token_new, email, new_pwd, current_pwd)
                if reverted:
                    print(f"Password reverted successfully for {email}")
                    store_log(email, current_pwd, new_pwd, True)
                else:
                    print(f"Failed to revert password for {email}")
                    store_log(email, current_pwd, new_pwd, False)
            else:
                print(f"Login failed with new password for {email}")
                store_log(email, current_pwd, new_pwd, False)
        else:
            print(f"Password change failed for {email}")
            store_log(email, current_pwd, new_pwd, False)

    print("\nPassword change test completed.")

if __name__ == "__main__":
    main()
