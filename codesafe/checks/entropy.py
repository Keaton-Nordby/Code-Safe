import math
import re

ENTROPY_THRESHOLD = 4.5  # tweak as needed
MIN_LENGTH = 20          # minimum length for a string to be considered

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def scan_file_for_entropy(file_path: str, content: str):
    """
    Scan content for high-entropy strings (likely secrets).
    Works on preprocessed content from scanner.py.
    """
    findings = []
    token_pattern = re.compile(r"[0-9A-Za-z+/=]{%d,}" % MIN_LENGTH)

    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        for match in token_pattern.findall(line):
            if shannon_entropy(match) > ENTROPY_THRESHOLD:
                findings.append({
                    "file": file_path,
                    "line": i,
                    "content": match
                })
    return findings
