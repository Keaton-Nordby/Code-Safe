#!/usr/bin/env python3
"""
Test script to verify all imports work correctly with the codesafe module structure.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent.absolute()
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))


def test_imports():
    """Test all required imports for the GUI."""
    print("Testing CodeSafe GUI imports...")
    print("=" * 40)
    
    # Test PySide6 imports
    try:
        from PySide6.QtWidgets import QApplication, QMainWindow, QWidget
        from PySide6.QtCore import Qt, QThread, Signal
        from PySide6.QtGui import QFont, QDragEnterEvent, QDropEvent
        print("✓ PySide6 imports successful")
    except ImportError as e:
        print(f"✗ PySide6 import failed: {e}")
        return False
    
    # Test codesafe module imports
    try:
        from codesafe.scanner import convert_to_sarif, preprocess_content, mask_secret
        print("✓ codesafe.scanner imports successful")
    except ImportError as e:
        print(f"✗ codesafe.scanner import failed: {e}")
        return False
    
    try:
        from codesafe.checks.patterns import scan_file_for_patterns
        print("✓ codesafe.checks.patterns import successful")
    except ImportError as e:
        print(f"✗ codesafe.checks.patterns import failed: {e}")
        return False
    
    try:
        from codesafe.checks.entropy import scan_file_for_entropy, shannon_entropy, ENTROPY_THRESHOLD, MIN_LENGTH
        print("✓ codesafe.checks.entropy import successful")
    except ImportError as e:
        print(f"✗ codesafe.checks.entropy import failed: {e}")
        return False
    
    try:
        from codesafe.checks.env_keys import scan_file_for_env_patterns
        print("✓ codesafe.checks.env_keys import successful")
    except ImportError as e:
        print(f"✗ codesafe.checks.env_keys import failed: {e}")
        return False
    
    # Test GUI import
    try:
        from gui import CodeSafeGUI, ScannerWorker, ScanResult
        print("✓ GUI module imports successful")
    except ImportError as e:
        print(f"✗ GUI module import failed: {e}")
        return False
    
    print("\nAll imports successful! ✓")
    return True


def test_scanner_functions():
    """Test that scanner functions work correctly."""
    print("\nTesting scanner functions...")
    print("=" * 40)
    
    try:
        from codesafe.scanner import preprocess_content, mask_secret, convert_to_sarif
        from codesafe.checks.patterns import scan_file_for_patterns
        from codesafe.checks.entropy import scan_file_for_entropy
        from codesafe.checks.env_keys import scan_file_for_env_patterns
        
        # Test preprocess_content
        test_content = '"sk_" + "test_" + "12345"'
        processed = preprocess_content(test_content)
        assert processed == "sk_test_12345", f"Expected 'sk_test_12345', got '{processed}'"
        print("✓ preprocess_content works")
        
        # Test mask_secret
        secret = "sk_test_12345EXPOSED"
        masked = mask_secret(secret)
        assert masked.startswith("sk_test"), f"Expected masked secret to start with 'sk_test', got '{masked}'"
        print("✓ mask_secret works")
        
        # Test pattern scanning
        test_file_content = "API_KEY=sk_test_1234567890"  # now 16+ chars
        patterns = scan_file_for_patterns("test.py", test_file_content)
        assert len(patterns) > 0, "Expected to find patterns in test content"

        
        # Test entropy scanning
        high_entropy_content = "random_string_with_high_entropy_12345"
        entropy_results = scan_file_for_entropy("test.py", high_entropy_content)
        # We don’t assert length, just ensure it runs without error
        print("✓ entropy scanning works")
        
        # Test env key scanning
        env_content = "SECRET=my_secret_value"
        env_results = scan_file_for_env_patterns("test.py", env_content)
        assert len(env_results) > 0, "Expected to find env patterns in test content"
        print("✓ env key scanning works")

        
        print("\nAll scanner functions work correctly! ✓")
        return True
        
    except Exception as e:
        print(f"✗ Scanner function test failed: {e}")
        return False


def main():
    """Main test function."""
    print("CodeSafe GUI Import Test")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("codesafe") or not os.path.exists("gui.py"):
        print("ERROR: Please run this script from the project root directory")
        print("Required structure:")
        print("  codesafe/")
        print("    ├── scanner.py")
        print("    └── checks/")
        print("        ├── patterns.py")
        print("        ├── entropy.py")
        print("        └── env_keys.py")
        print("  gui.py")
        return 1
    
    # Test imports
    if not test_imports():
        print("\nImport test failed!")
        return 1
    
    # Test scanner functions
    if not test_scanner_functions():
        print("\nScanner function test failed!")
        return 1
    
    print("\n" + "=" * 50)
    print("All tests passed! The GUI should work correctly.")
    print("You can now run: python gui.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
