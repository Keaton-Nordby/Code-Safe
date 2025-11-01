import os
import json
import re
import argparse
from colorama import Fore, Style, init

# Correct imports from codesafe package
from codesafe.checks.patterns import scan_file_for_patterns
from codesafe.checks.entropy import scan_file_for_entropy
from codesafe.checks.env_keys import scan_file_for_env_patterns

init(autoreset=True)

# --- Helpers ---
def preprocess_content(content: str) -> str:
    """
    Normalize file content to catch buried/concatenated secrets.
    Example: "sk_" + "test_" + "12345" -> sk_test_12345
    """
    # Remove concatenation quotes
    content = re.sub(r'["\']\s*\+\s*["\']', '', content)
    # Remove surrounding quotes from strings
    content = re.sub(r'^["\']|["\']$', '', content)
    return content


def mask_secret(secret: str, visible: int = 7) -> str:
    """
    Mask secret values so reports/logs don’t expose them.
    Example: sk_test_12345EXPOSED -> sk_test_*********
    """
    if len(secret) <= visible:
        return secret
    return secret[:visible] + "*" * (len(secret) - visible)


def color_severity(severity: str) -> str:
    """Return colored severity for console output."""
    if severity == "high":
        return Fore.RED + severity + Style.RESET_ALL
    elif severity == "medium":
        return Fore.YELLOW + severity + Style.RESET_ALL
    else:
        return severity


def convert_to_sarif(findings):
    """
    Convert findings to GitHub SARIF format for code scanning.
    """
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeSafe",
                    "informationUri": "",  # Removed GitHub link
                    "rules": []
                }
            },
            "results": []
        }]
    }

    for idx, f in enumerate(findings, 1):
        result = {
            "ruleId": f"CS-{idx}",
            "level": "warning",
            "message": {"text": f"Potential secret ({f['type']}, {f['severity']}): {mask_secret(f['content'])}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]}
                }
            }]
        }
        sarif["runs"][0]["results"].append(result)
    return sarif


# --- Main Scanner ---
def run_scan(args):
    all_findings = []

    for root_dir, dirs, files in os.walk(args.root):
        # Skip common folders
        skip_dirs = {"node_modules", ".git", "dist", "build", ".venv", "venv", ".tox", "target", ".idea", ".vscode"}
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for file in files:
            file_path = os.path.join(root_dir, file)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_content = f.read()
                content = preprocess_content(raw_content)
            except Exception:
                continue  # skip unreadable files

            # --- Run checks ---
            all_findings.extend(
                [{**f, "type": "pattern"} for f in scan_file_for_patterns(file_path, content)]
            )
            all_findings.extend(
                [{**f, "type": "entropy"} for f in scan_file_for_entropy(file_path, content)]
            )
            all_findings.extend(
                [{**f, "type": "env"} for f in scan_file_for_env_patterns(file_path, content)]
            )

    # --- Assign severity ---
    for f in all_findings:
        if f["type"] == "pattern":
            f["severity"] = "high"
        else:
            f["severity"] = "medium"

    # --- Deduplicate findings ---
    unique_findings = list({(f['file'], f['line']): f for f in all_findings}.values())
    all_findings = unique_findings

    # --- Console output ---
    if all_findings:
        print("⚠️ Findings:\n")
        print(f"{'File':<50} {'Line':<5} {'Type':<8} {'Severity':<8} {'Secret'}")
        print("-" * 100)
        for f in all_findings:
            file_display = f['file'][-50:]  # show last 50 chars
            line_display = f"{f['line']:<5}"
            type_display = f"{f['type']:<8}"
            severity_display = f"{color_severity(f['severity']):<8}"
            secret_display = mask_secret(f['content'], visible=7)
            print(f"{file_display:<50} {line_display} {type_display} {severity_display} {secret_display}")
    else:
        print("✅ No secrets found!")

    # --- JSON output ---
    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(all_findings, jf, indent=2)
        print(f"JSON report saved to {args.json}")

    # --- SARIF output ---
    if args.sarif:
        sarif_report = convert_to_sarif(all_findings)
        with open(args.sarif, "w", encoding="utf-8") as sf:
            json.dump(sarif_report, sf, indent=2)
        print(f"SARIF report saved to {args.sarif}")


def main():
    parser = argparse.ArgumentParser(description="CodeSafe - Secret Scanner for Developers")
    parser.add_argument("--root", default=".", help="Root folder to scan")
    parser.add_argument("--json", help="Save JSON report")
    parser.add_argument("--sarif", help="Save SARIF report")
    args = parser.parse_args()
    run_scan(args)


if __name__ == "__main__":
    main()
