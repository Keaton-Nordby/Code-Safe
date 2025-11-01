import argparse
from codesafe.scanner import run_scan

def main():
    parser = argparse.ArgumentParser(description="CodeSafe - Secret scanner")
    parser.add_argument("root", help="Folder to scan")
    parser.add_argument("--json", help="Output JSON file")
    parser.add_argument("--sarif", help="Output SARIF file")
    parser.add_argument("--git-history", action="store_true", help="Scan git history")
    parser.add_argument("--exclude", help="Regex pattern to exclude folders/files")
    args = parser.parse_args()

    run_scan(args)

if __name__ == "__main__":
    main()
