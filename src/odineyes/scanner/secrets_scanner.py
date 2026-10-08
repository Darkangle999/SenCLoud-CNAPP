from __future__ import annotations
import os
import re
import math
import hashlib
from odineyes.cloud.models import SecretFinding

class SecretsScanner:
    """
    Phase 4: Secrets & Identity Scanner.
    Scans a mounted EBS snapshot for plaintext credentials.
    Calculates Shannon entropy to discard low-entropy placeholders.
    NEVER stores the raw secret value.
    """

    def __init__(self, snapshot_mount_path: str):
        self.snapshot_mount_path = snapshot_mount_path
        
        self.patterns = {
            "AWS_ACCESS_KEY": re.compile(r'AKIA[0-9A-Z]{16}'),
            "GITHUB_TOKEN": re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            "PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY'),
            "ENV_PASSWORD": re.compile(r'(?:PASSWORD|SECRET|TOKEN|KEY)=([^\s]+)'),
            "AWS_SECRET_KEY": re.compile(r'[0-9a-zA-Z/+]{40}')
        }

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy

    def scan(self) -> list[SecretFinding]:
        findings = []
        skip_dirs = ['/proc', '/sys', '/dev', '/run', 'node_modules', '.git', '__pycache__', '.venv', 'venv']
        
        for root, dirs, files in os.walk(self.snapshot_mount_path):
            # Skip directories
            dirs[:] = [d for d in dirs if not any(skip in os.path.join(root, d) for skip in skip_dirs)]
            
            for filename in files:
                if filename.endswith(".pyc"):
                    continue
                    
                filepath = os.path.join(root, filename)
                
                # Context flags for AWS_SECRET_KEY
                is_env_or_cred = filename == ".env" or filename == "credentials"
                
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        lines = f.readlines()
                except Exception:
                    continue

                print(f"Scanning: {filepath}")
                keywords = ["secret", "key", "token", "password", "credential", "api"]
                
                for line_idx, line in enumerate(lines):
                    for secret_type, pattern in self.patterns.items():
                        matches = pattern.findall(line)
                        for match in matches:
                            raw_value = match if isinstance(match, str) else line.strip()
                            
                            entropy = self._calculate_entropy(raw_value)
                            if entropy < 3.5:
                                continue

                            # Context window check
                            start_idx = max(0, line_idx - 3)
                            end_idx = min(len(lines), line_idx + 4)
                            context_lines = "".join(lines[start_idx:end_idx]).lower()
                            
                            if not any(k in context_lines for k in keywords):
                                continue

                            value_hash = hashlib.sha256(raw_value.encode()).hexdigest()
                            
                            findings.append(SecretFinding(
                                secret_type=secret_type,
                                file_path=filepath,
                                value_hash=value_hash,
                                entropy_score=entropy,
                                line_number=line_idx + 1
                            ))
                            
        return findings
