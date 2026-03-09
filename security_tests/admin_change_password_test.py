import requests
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_LOGIN_URL = f"{BASE_URL}/admin/login-admin"
USER_LOGIN_URL = f"{BASE_URL}/user/login"
CHANGE_PWD_URL = f"{BASE_URL}/admin/change-password"
CRED_FILE = "creds.txt"
LOG_FILE = "admin_pwd_change.log"

def read_creds(file_path):
    users, admins = [], []
    with open(file_path, "r") as f:
        for line in f:
            if line.strip():
                parts = line.strip().split(',')
                if len(parts) == 3:
                    entry = {"email": parts[0], "password": parts[1], "role": parts[2]}
                    if parts[2].lower() == "admin":
                        admins.append(entry)
                    elif parts[2].lower() == "user":
                        users.append(entry)
    return admins, users

def login(email, password, role="user"):
    url = ADMIN_LOGIN_URL if role.lower() == "admin" else USER_LOGIN_URL
    payload = {"username_or_email": email, "password": password}
    try:
        resp = requests.post(url, json=payload)
        if resp.status_code == 200:
            return resp.json().get("access_token")
    except Exception as e:
        print(f"Login error for {email}: {e}")
    return None

def admin_change_pwd(token, user_email, new_password):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "email": user_email,
        "new_password": new_password,
        "confirm_password": new_password
    }
    try:
        resp = requests.post(CHANGE_PWD_URL, json=payload, headers=headers)
        return resp.status_code == 200, resp.text
    except Exception as e:
        return False, str(e)
    
def log_event(message):
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.ctime()} | {message}\n")

def main():
    admins, users = read_creds(CRED_FILE)
    if not admins:
        print("No admin credentials found in the file.")
        return
    
    admin = admins[0]
    admin_email = admin["email"]
    admin_pwd = admin["password"]

    print(f"Logging in as admin: {admin_email}")
    admin_token = login(admin_email, admin_pwd, role="admin")
    if not admin_token:
        log_event(f"[ADMIN LOGIN FAILED] {admin_email}")
        print(f"Admin login failed for {admin_email}.")
        return
    
    log_event(f"[ADMIN LOGIN] Success for {admin_email}")
    print("Admin login successful\n")

    for user in users:
        user_email = user["email"]
        old_pwd = user["password"]
        new_pwd = f"{old_pwd}_New"

        print(f"Changing password for user: {user_email}")
        success, message = admin_change_pwd(admin_token, user_email, new_pwd)
        if success:
            log_event(f"[PASSWORD CHANGE]  Success for {user_email} from {old_pwd} to {new_pwd}")
            print(f"Password changed successfully for {user_email}")

            user_token = login(user_email, new_pwd, role="user")
            if user_token:
                log_event(f"[USER LOGIN] Success with new password for {user_email}")
                print(f"User login successful with new password for {user_email}")

                reverted, revert_msg = admin_change_pwd(admin_token, user_email, old_pwd)
                if reverted:
                    log_event(f"[REVERT] Reverted password for {user_email} back to {old_pwd}")
                    print(f"Password reverted successfully for {user_email}")
                else:
                    log_event(f"[REVERT FAILED] Could not revert {user_email}: {revert_msg}")
                    print(f"Failed to revert password for {user_email}")

            else:
                log_event(f"[USER LOGIN FAILED] {user_email} failed login with new password")
                print(f"Login with new password failed for {user_email}")
        else:
            log_event(f"[PASSWORD CHANGE FAILED] Could not change password for {user_email}: {message}")
            print(f"Password change failed for {user_email}")
    
    print("\nAdmin change password test completed.")

if __name__ == "__main__":
    main()