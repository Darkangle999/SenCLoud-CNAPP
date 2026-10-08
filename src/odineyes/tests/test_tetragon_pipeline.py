"""End-to-End simulation of Tetragon logs to Detection Engine.

This script creates a dummy Tetragon log file, writes mock JSON events 
that represent a reverse shell and a sensitive file read, then parses 
those events exactly how `tetragon_shipper.py` does, and feeds them 
into the Odineyes `DetectionEngine` to verify that anomalies 
are correctly flagged.
"""

import json
import tempfile
import time
from typing import List

from odineyes.sensor import tetragon_shipper
from odineyes.sensor.detection import DetectionEngine

def generate_mock_logs(file_path: str):
    """Writes mock Tetragon JSON logs to the file."""
    events = [
        # 1. Normal benign command
        {
            "process_exec": {
                "process": {
                    "binary": "/bin/ls",
                    "arguments": "-la",
                    "pid": 100,
                    "pod": {"name": "app-pod"}
                }
            }
        },
        # 2. Sensitive File Access
        {
            "process_kprobe": {
                "function_name": "sys_openat",
                "process": {
                    "binary": "/bin/cat",
                    "pid": 101,
                    "pod": {"name": "app-pod"}
                },
                "args": [{"string_arg": "/etc/shadow"}]
            }
        },
        # 3. Reverse Shell execution & connect (Two events typically correlated)
        {
            "process_exec": {
                "process": {
                    "binary": "/bin/bash",
                    "arguments": "-i",
                    "pid": 102,
                    "pod": {"name": "app-pod"}
                },
                "parent": {
                    "binary": "/usr/sbin/nginx" # Web server spawning shell -> RT-001
                }
            }
        },
        {
            "process_kprobe": {
                "function_name": "tcp_connect",
                "process": {
                    "binary": "/bin/bash",
                    "pid": 102,
                    "pod": {"name": "app-pod"}
                },
                "parent": {
                    "binary": "/bin/bash" # Shell connecting out -> RT-002
                },
                "dest": "8.8.8.8:4444"
            }
        }
    ]

    with open(file_path, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def test_pipeline():
    engine = DetectionEngine(baseline_learning=False)
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        log_path = tmp.name
        
    print(f"[*] Generating mock Tetragon logs at: {log_path}")
    generate_mock_logs(log_path)
    
    print("[*] Tailing and parsing logs through tetragon_shipper...")
    batch = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            # 1. Shipper parses the raw JSON
            raw_event = tetragon_shipper.parse_tetragon_event(line)
            if not raw_event:
                continue
                
            # 2. Shipper normalizes it for the detection engine
            normalized_event = tetragon_shipper.normalize_for_detection(raw_event["raw"])
            
            # Combine the base event data with the normalized detection fields
            full_event = {**raw_event, **normalized_event}
            
            print(f"\n[Incoming Event]: {full_event.get('summary', 'Unknown')}")
            import pprint
            pprint.pprint(full_event)
            
            # 3. Detection Engine evaluates the event
            findings = engine.feed(full_event)
            
            if findings:
                print(f"  [!] ANOMALY DETECTED:")
                for finding in findings:
                    print(f"      -> Rule: {finding.rule_id} - Severity: {finding.severity}")
            else:
                print("  [OK] Event cleared (Benign)")
            
            # Batch for shipping
            batch.append(full_event)

    # 4. Ship to the live backend so it appears on the Web Dashboard
    print(f"\n[*] Shipping {len(batch)} events to the local Odineyes backend (http://127.0.0.1:8000)...")
    try:
        tetragon_shipper.ship_events("http://127.0.0.1:8000", batch, "default")
        print("  [OK] Successfully shipped to backend! Check your Threats Dashboard on the website.")
    except Exception as e:
        print(f"  [X] Failed to ship (Is the backend running on port 8000?): {e}")

if __name__ == "__main__":
    test_pipeline()
