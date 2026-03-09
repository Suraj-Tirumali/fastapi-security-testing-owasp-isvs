import requests

BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = f"{BASE_URL}/user/login"
RESOURCE_DETAILS_URL = f"{BASE_URL}/resource/resource-details"
CRED_FILE = "cred.txt"

def read_cred(file_path):
    users = []
    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                users.append({"username": parts[0], "password": parts[1]})
    return users

def login_user(user):
    try:
        resp = requests.post(LOGIN_URL, json={"username_or_email": user["username"], "password": user["password"]})
        if resp.ok and "access_token" in resp.json():
            return resp.json()["access_token"]
    except Exception as e:
        print(f"Login failed for {user['username']}: {e}")
    return None

def get_resource_ids(token):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(RESOURCE_DETAILS_URL, headers=headers)
        if resp.ok:
            data  = resp.json()
            return [d["resource_id"] for d in data if "resource_id" in d]
        else:
            print(f"Failed to get resource details: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"Failed to fetch resource details: {e}")
    return []

def check_global_resource_id_uniqueness():
    creds = read_cred(CRED_FILE)
    print("Loaded credentials:", creds)

    all_ids = {}
    duplicates = []

    for cred in creds:
        token = login_user(cred)
        if not token:
            print(f"Could not login as {cred['username']}")
            continue
        else:
            print(f"Logged in as {cred['username']}")

        resource_ids = get_resource_ids(token)
        print(f"[{cred['username']}] Resource IDs: {resource_ids}")

        for resource_id in resource_ids:
            if resource_id in all_ids:
                duplicates.append((resource_id, all_ids[resource_id], cred['username']))
            else:
                all_ids[resource_id] = cred['username']

    if duplicates:
        print("\n Duplicate resource IDs found across users:")
        for resource_id, user_a, user_b in duplicates:
            print(f" - Resource ID '{resource_id}' used by both {user_a} and {user_b}")
    else:
        print("\n All resource IDs are globally unique")

if __name__ == "__main__":
    check_global_resource_id_uniqueness()
