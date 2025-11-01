#!/usr/bin/env python3
"""
Simple launcher script for CodeSafe GUI.

This script ensures the GUI can be run from anywhere and handles
any import path issues with the codesafe module structure.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path to ensure imports work
current_dir = Path(__file__).parent.absolute()
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

try:
    from gui import main
    if __name__ == "__main__":
        main()
except ImportError as e:
    print(f"Error importing GUI: {e}")
    print("Make sure you're running this from the project root directory.")
    print("Required files: gui.py, codesafe/")
    print("Required structure:")
    print("  codesafe/")
    print("    ├── scanner.py")
    print("    └── checks/")
    print("        ├── patterns.py")
    print("        ├── entropy.py")
    print("        └── env_keys.py")
    sys.exit(1)
except Exception as e:
    print(f"Error starting GUI: {e}")
    sys.exit(1)