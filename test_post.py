import urllib.request
import json

url = "http://localhost:8000/api/inventory/accounts/onboarding-template"
data = json.dumps({"provider": "aws", "account_identifier": "441586174413", "name": "krizna"}).encode('utf-8')
req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

try:
    with urllib.request.urlopen(req) as response:
        print("Status:", response.status)
        print("Body:", response.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print("HTTP Error Status:", e.code)
    print("Error Body:", e.read().decode('utf-8'))
except Exception as e:
    print("Other Error:", e)
