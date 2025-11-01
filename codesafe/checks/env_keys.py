import re
import os

ENV_KEY_PATTERNS = [
    re.compile(r'^[A-Z0-9_]*API[_-]?KEY\s*=\s*.+', re.IGNORECASE),
    re.compile(r'^[A-Z0-9_]*SECRET\s*=\s*.+', re.IGNORECASE),
    re.compile(r'^[A-Z0-9_]*TOKEN\s*=\s*.+', re.IGNORECASE),
    re.compile(r'^[A-Z0-9_]*PASSWORD\s*=\s*.+', re.IGNORECASE),
    re.compile(r'^[A-Z0-9_]*PRIVATE[_-]?KEY\s*=\s*.+', re.IGNORECASE),
]

def scan_file_for_env_patterns(file_path: str, content: str):
    """
    Scan content for environment-variable-style secrets.
    Skips .env files (assumed intentional secret storage).
    """
    findings = []

    if os.path.basename(file_path).lower() == ".env":
        return findings

    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        for pattern in ENV_KEY_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "file": file_path,
                    "line": i,
                    "content": line.strip()
                })
    return findings
