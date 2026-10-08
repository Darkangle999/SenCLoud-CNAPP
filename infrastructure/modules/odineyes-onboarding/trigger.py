import json
import sys
import hmac
import hashlib
import time
import urllib.request
import urllib.error
import urllib.parse

def log(message):
    print(message, file=sys.stderr)

def main():
    try:
        # Read input from Terraform external data source
        input_data = sys.stdin.read()
        if not input_data:
            return
        query = json.loads(input_data)
    except Exception as e:
        log(f"Failed to read input: {e}")
        sys.exit(1)

    api_url = query.get('api_url')
    api_key = query.get('api_key')
    api_secret = query.get('api_secret')
    external_id = query.get('external_id')
    role_arn = query.get('role_arn')
    cloud = query.get('cloud', 'aws')

    if not all([api_url, api_key, api_secret, external_id, role_arn]):
        log("Missing required parameters for autoconnect")
        sys.exit(1)

    url = f"{api_url.rstrip('/')}/api/inventory/accounts/autoconnect"
    tstmp = str(int(time.time() * 1000))
    
    body_dict = {
        "external_id": external_id,
        "role_arn": role_arn,
        "cloud": cloud
    }
    body_bytes = json.dumps(body_dict).encode('utf-8')
    
    path = urllib.parse.urlparse(url).path

    # Compute HMAC signature
    enc = tstmp + "POST" + path + body_bytes.decode('utf-8')
    sig = hmac.new(
        api_secret.encode('utf-8'),
        enc.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    req = urllib.request.Request(url, data=body_bytes, method="POST")
    req.add_header("X-API-Key", api_key)
    req.add_header("X-Signature", sig)
    req.add_header("X-Timestamp", tstmp)
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode('utf-8')
            log(f"Autoconnect response: {response.status} {res_body}")
            # Output to terraform
            print(json.dumps({"status": "connected"}))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        log(f"Autoconnect failed with HTTP {e.code}: {err_body}")
        # Return error status to terraform but don't fail the deployment
        print(json.dumps({"status": f"failed: {e.code}"}))
    except Exception as e:
        log(f"Autoconnect failed: {e}")
        print(json.dumps({"status": "error"}))

if __name__ == "__main__":
    main()
