import json, urllib.request

resp = urllib.request.urlopen('http://localhost:8000/api/inventory/compliance/report?account_id=1&frameworks=CIS')
d = json.loads(resp.read())
cis = d['compliance']['CIS']
controls = cis['controls']

fail_controls = [c for c in controls if c['state'] == 'fail']
pass_controls = [c for c in controls if c['state'] == 'pass']
na_controls = [c for c in controls if c['state'] == 'not_assessed']
print(f"FAIL: {len(fail_controls)}, PASS: {len(pass_controls)}, NA: {len(na_controls)}")
print(f"Score: {cis['score']}  passing: {cis['passing']}  total: {cis['total']}")

# Show controls that should be failing based on the findings
# Findings had: CIS 5.2, 2.1.1, 2.1.5, 3.7, 3.4, 3.2, 2.8, 5.4
target_ids = ['5.2', '3.7', '3.4', '3.2', '2.8', '2.1.1', '2.1.5', '5.4']
for c in controls:
    if c['id'] in target_ids:
        print(f"  Control {c['id']}: state={c['state']}  checks={c.get('checks', [])}")

# Print ALL failing controls
print("\nAll failing controls:")
for c in fail_controls:
    print(f"  {c['id']}: checks={c.get('checks', [])}")
