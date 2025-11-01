import re

# Regex patterns for common secrets
SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                        # AWS Access Key
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                  # Google API Key
    re.compile(r'(?i)(api[_-]?key|secret)[\"\'\s:=]+[0-9A-Za-z\-_=]{16,}'),  # Generic API keys
    re.compile(r'Bearer\s+[0-9a-zA-Z\-\._]+'),              # Bearer tokens
    re.compile(r'-----BEGIN( RSA)? PRIVATE KEY-----'),      # Private keys
]

def scan_file_for_patterns(file_path: str, content: str):
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        for pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "file": file_path,
                    "line": i,
                    "content": line.strip()
                })
    return findings

