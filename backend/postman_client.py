import json, requests, argparse, re
import sys

POSTMAN_COLLECTION_FILE = "FastAPI.postman_collection.json"
BASE_URL = "http://127.0.0.1:8000"

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        collection = json.load(file)

    endpoints = {}

    def traverse_items(items):
        for item in items:
            if 'request' in item:
                req = item['request']
                raw = req.get('url', {}).get('raw', '')
                if "{{baseUrl}}" in raw:
                    key = raw.replace("{{baseUrl}}", "").lstrip("/")
                    endpoints[key] = req
            elif 'item' in item:
                traverse_items(item['item'])

    traverse_items(collection["item"])
    return endpoints

def parse_params(param_list):
    result = {}
    current_key = None
    current_value = []

    for token in param_list or []:
        if "=" in token:
            if current_key:
                result[current_key] = " ".join(current_value)
            current_key, val = token.split("=", 1)
            current_value = [val]
        else:
            current_value.append(token)

    if current_key:
        result[current_key] = " ".join(current_value)

    return result

def extract_path_vars(path):
    return re.findall(r":(\w+)", path)

def sub_path_vars(path_template, vars):
    for key, value in vars.items():
        path_template = path_template.replace(f":{key}", str(value))
    return path_template

def find_endpoint(collection, endpoint_path):
    normalized_path = endpoint_path.strip("/")
    if normalized_path in collection:
        return collection[normalized_path]

    print("DEBUG: Available endpoints:")
    for key in collection:
        print("-", key)

    return None

def prompt_for_body(body_template):
    try:
        template = json.loads(body_template)
        collected = {}
        for key in template:
            val  = input(f"Enter value for {key}:")
            collected[key] = val
        return collected
    except Exception:
        print("Invalid body template. Provide JSON manually:")
        return json.loads(input("Enter request body as JSON:"))
    
def make_req(req, path_vars, body_args, token):
    url = req['url']
    raw_url = url.get('raw')

    if raw_url and "{{baseUrl}}" in raw_url:
        final_url = raw_url.replace("{{baseUrl}}", BASE_URL)
    else:
        final_url = raw_url

    final_url = sub_path_vars(final_url, path_vars)
    full_url = BASE_URL + final_url if final_url and not final_url.startswith("http") else final_url

    method = req['method'].upper()
    headers = {h['key']: h['value'] for h in req.get('header', [])}

    if token:
        for k in headers:
            if "{{token}}" in headers[k]:
                headers[k] = headers[k].replace("{{token}}", token)
        headers["Authorization"] = f"Bearer {token}"

    body = None

    if 'body' in req and req['body']['mode'] == 'raw':
        if body_args:
            body = json.dumps(body_args)
        else:
            print("\nNo --body provided. Prompting for input field-by-field")
            body = json.dumps(prompt_for_body(req['body']['raw']))

    print(f"\nMaking {method} request to : {full_url}")
    response = requests.request(method, full_url, headers=headers, data=body)

    print(f"\nStatus: {response.status_code}")
    try:
        parsed = response.json()
        pretty = json.dumps(parsed, indent=2)
        print("Response:\n", pretty)
    except ValueError:
        print("Response:\n", response.text)

def main():
    parser = argparse.ArgumentParser(description="Simulate Postman requests from collection.")
    parser.add_argument("--endpoint", required=True, help="API endpoint (e.g., /user/{user_uid})")
    parser.add_argument("--params", nargs='*', help="Path parameters as key=value")
    parser.add_argument("--body", type=str, help="Request body as JSON string")
    parser.add_argument("--token", type=str, help="Bearer token to authenticate requests")

    args = parser.parse_args()
    postman = load_postman_collection(POSTMAN_COLLECTION_FILE)
    endpoint_path = args.endpoint.strip()
    request_data = find_endpoint(postman, endpoint_path)
    
    if not request_data:
        print(f"[ERROR] Endpoint '{endpoint_path}' not found in collection.")
        sys.exit(1)

    path_params = parse_params(args.params)
    body_args = json.loads(args.body) if args.body else {}

    make_req(request_data, path_params, body_args, args.token)

if __name__ == "__main__":
    main()