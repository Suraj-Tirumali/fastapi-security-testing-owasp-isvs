import requests
import ssl
import socket
import argparse
from urllib.parse import urlparse

USER_DETAILS_URL = "http://127.0.0.1:8000/user/user_details"
RESOURCE_DETAILS_URL = "http://127.0.0.1:8000/resource/resource-details"

def check_jwt(response_json):
    token = response_json.get("access_token")
    if not token:
        return False
    jwt_parts = token.split('.')
    if len(jwt_parts) != 3:
        return False
    print("JWT token found and looks valid")
    return True

def check_sas_token(response_json):
    for key, value in response_json.items():
        if isinstance(value, str) and ("sig=" in value or "se=" in value):
            print(f"Possible SAS token found in response key '{key}'")
            return True
    return False

def check_tls_client_cert(host):
    hostname = urlparse(host).hostname
    port = 443
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    print(f"x.509 Certificate presented by server")
                    return True
    except ssl.SSLError as e:
        if "tlsv13 alert certificate required" in str(e).lower():
            print("Server requires x.509 client certificate (mTLS)")
            return True
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Error connecting to {hostname}: {e}")
    return False

def read_credentials(file_path):
    users = []
    with open(file_path, 'r') as file:
        for line in file:
            if "," in line:
                email, password = line.strip().split(",", 1)
                users.append((email.strip(), password.strip()))
    return users

def login_user(login_url, email, password):
    try:
        resp = requests.post(login_url, json={
            "username_or_email": email,
            "password": password
        })
        if resp.status_code == 200:
            return resp.json().get("access_token")
        else:
            print(f"Login failed for {email}: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        print(f"Error logging in {email}: {e}")
        return None
    
def get_protected_details(token, url):
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        status_code = resp.status_code
        data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
        return status_code, data
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return None, {}
    
def compare_identity_fields(a, b):
    keys = ["uid", "username", "email", "phone_number", "role"]
    mismatches = {}
    for key in keys:
        if a.get(key) != b.get(key):
            mismatches[key] = (a.get(key), b.get(key))
    return mismatches

def run_idor_check(login_url, creds_file):
    creds = read_credentials(creds_file)
    users = {}
    baseline_data = {}

    print(f"Logging in users and storing tokens...")
    for email, password in creds:
        token = login_user(login_url, email, password)
        if token:
            users[email] = token

    print(f"Accessing protected endpoints")
    for email, token in users.items():
        user_status, user_data = get_protected_details(token, USER_DETAILS_URL)
        resource_status, resource_data = get_protected_details(token, RESOURCE_DETAILS_URL)

        baseline_data[email] = {
            "token": token,
            "user_details": user_data if user_status ==  200 else {},
            "resource_details": resource_data if resource_status == 200 else {}
        }
    print(f"\nSwapping tokens and checking for IDOR vulnerablities\n")

    for email_a, token_a in users.items():
        for email_b, token_b in users.items():
            if email_a == email_b:
                continue

            print(f"Trying to access {email_a}'s data with {email_b}'s token")

            status, data = get_protected_details(token_b, USER_DETAILS_URL)
            if status == 200:
                mismatches = compare_identity_fields(data, baseline_data[email_b]["user_details"])
                if mismatches:
                    print(f"IDOR Detected on /user/user_details - mismatches: {mismatches}")
                elif data != baseline_data[email_b]["user_details"]:
                    print(f"Poosbile data leak on /user/user_details: response differs")
                else:
                    print(f"Access properly restricted for /user/user_details")
            else:
                print(f"Access denied with status code {status} for /user/user_details")

            status, data = get_protected_details(token_b, RESOURCE_DETAILS_URL)
            if status == 200:
                if data != baseline_data[email_b]["resource_details"]:
                    print(f"IDOR detected on /deivce/deivce_details: response differs")
                else:
                    print(f"Access properly restricted for /resource/resource-details")
            else:
                print(f"Access denied with status code {status} for /resource/resource-details")

    print("\nIDOR check completed!")

def main():
    parser = argparse.ArgumentParser(description="Auth scheme compliance and IDOR vulnerabilities")
    parser.add_argument("--url", required=True, help="Login API URL")
    parser.add_argument("--idor", help="Run IDOR check with provided credentials file")

    args = parser.parse_args()

    if args.idor:
        run_idor_check(args.url, args.idor)
    else:
        print("Attempting login via: {args.url}")
        creds = read_credentials("cred.txt")
        if not creds:
            print("No credentials found in cred.txt")
            return
        
        email, password = creds[0]
        try:
            resp = requests.post(args.url, json={"username_or_email": email, "password": password})
            if resp.status_code != 200:
                print(f"Login failed: {resp.status_code}: {resp.text}")
                return
            
            resp_json = resp.json()
            print(f"Login successful. Verifying authentication mechanisms:\n")

            if not check_jwt(resp_json):
                print("No valid JWT token found")

            if not check_sas_token(resp_json):
                print("No SAS token found")

            if not check_tls_client_cert(args.url):
                print("Server does not enforce or present client-side x.509 authentication")

        except Exception as e:
            print(f"Error during request: {e}")

if __name__ == "__main__":
    main()
