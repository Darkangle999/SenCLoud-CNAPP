import json
import urllib.request

# Test account_id=1
resp = urllib.request.urlopen('http://localhost:8000/api/inventory/compliance/report?account_id=1')
data = json.loads(resp.read())

for fw_id, fw in data.get('compliance', {}).items():
    score = fw.get('score')
    passing = fw.get('passing')
    failing = fw.get('failing')
    total = fw.get('total')
    not_assessed = fw.get('not_assessed')
    print(f"FW={fw_id}  score={score}  passing={passing}  failing={failing}  total={total}  not_assessed={not_assessed}")
    controls = fw.get('controls', [])
    states = {}
    for c in controls:
        s = c['state']
        states[s] = states.get(s, 0) + 1
    print(f"  Control states: {states}")
    # Print first 5 controls
    for c in controls[:5]:
        print(f"  {c['id']}: state={c['state']}  checks={c.get('checks', [])}")

# Also check: does ScanJob exist?
print("\n--- Checking ScanJob table ---")
resp2 = urllib.request.urlopen('http://localhost:8000/api/inventory/accounts')
accts = json.loads(resp2.read())
print(f"Accounts: {json.dumps(accts, indent=2)[:1000]}")
