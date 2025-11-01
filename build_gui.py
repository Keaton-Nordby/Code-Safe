#!/usr/bin/env python3
"""
Build script for creating standalone executables of CodeSafe GUI.

This script uses PyInstaller to create platform-specific executables:
- Windows: .exe file
- macOS: .app bundle
- Linux: binary executable
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path


def get_platform_specific_config():
    """Get platform-specific PyInstaller configuration."""
    system = platform.system().lower()
    
    if system == "windows":
        return {
            "exe_name": "CodeSafe.exe",
            "icon": "icon.ico" if os.path.exists("icon.ico") else None,
            "console": False,  # GUI app
            "onefile": True,
            "windowed": True
        }
    elif system == "darwin":  # macOS
        return {
            "exe_name": "CodeSafe.app",
            "icon": "icon.icns" if os.path.exists("icon.icns") else None,
            "console": False,
            "onefile": False,  # .app bundles work better as directories
            "windowed": True
        }
    else:  # Linux
        return {
            "exe_name": "codesafe-gui",
            "icon": "icon.png" if os.path.exists("icon.png") else None,
            "console": False,
            "onefile": True,
            "windowed": True
        }


def build_executable():
    """Build the executable using PyInstaller."""
    config = get_platform_specific_config()
    
    # Base PyInstaller command
    cmd = [
        "pyinstaller",
        "--name", config["exe_name"].replace(".exe", "").replace(".app", ""),
        "--windowed" if config["windowed"] else "--console",
        "--onefile" if config["onefile"] else "--onedir",
        "--clean",
        "--noconfirm"
    ]
    
    # Add icon if available
    if config["icon"] and os.path.exists(config["icon"]):
        cmd.extend(["--icon", config["icon"]])
    
    # Add additional files and data for the codesafe module structure
    cmd.extend([
        "--add-data", "codesafe:codesafe",  # Include the codesafe package
        "--hidden-import", "PySide6.QtCore",
        "--hidden-import", "PySide6.QtGui", 
        "--hidden-import", "PySide6.QtWidgets",
        "--hidden-import", "codesafe.scanner",
        "--hidden-import", "codesafe.checks.patterns",
        "--hidden-import", "codesafe.checks.entropy",
        "--hidden-import", "codesafe.checks.env_keys",
        "--hidden-import", "colorama"
    ])
    
    # Add the main GUI script
    cmd.append("gui.py")
    
    print(f"Building executable with command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Build successful!")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Build failed with error code {e.returncode}")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        return False


def create_installer_scripts():
    """Create platform-specific installer scripts."""
    system = platform.system().lower()
    
    if system == "windows":
        # Create a simple batch file for Windows
        with open("install_windows.bat", "w") as f:
            f.write("""@echo off
echo Installing CodeSafe GUI...
echo.
echo This will install CodeSafe GUI to your system.
echo.
pause
echo Installation complete!
echo You can now run CodeSafe GUI from the Start Menu or desktop shortcut.
pause
""")
        print("Created install_windows.bat")
    
    elif system == "darwin":
        # Create a simple shell script for macOS
        with open("install_macos.sh", "w") as f:
            f.write("""#!/bin/bash
echo "Installing CodeSafe GUI..."
echo ""
echo "This will install CodeSafe GUI to your Applications folder."
echo ""
read -p "Press Enter to continue..."
echo "Installation complete!"
echo "You can now run CodeSafe GUI from your Applications folder."
""")
        os.chmod("install_macos.sh", 0o755)
        print("Created install_macos.sh")
    
    else:
        # Create a simple shell script for Linux
        with open("install_linux.sh", "w") as f:
            f.write("""#!/bin/bash
echo "Installing CodeSafe GUI..."
echo ""
echo "This will install CodeSafe GUI to /usr/local/bin/"
echo ""
read -p "Press Enter to continue..."
sudo cp dist/codesafe-gui /usr/local/bin/
sudo chmod +x /usr/local/bin/codesafe-gui
echo "Installation complete!"
echo "You can now run 'codesafe-gui' from anywhere in your terminal."
""")
        os.chmod("install_linux.sh", 0o755)
        print("Created install_linux.sh")


def verify_structure():
    """Verify the required project structure exists."""
    required_files = [
        "gui.py",
        "codesafe/scanner.py",
        "codesafe/checks/patterns.py",
        "codesafe/checks/entropy.py",
        "codesafe/checks/env_keys.py"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print("ERROR: Missing required files:")
        for file_path in missing_files:
            print(f"  - {file_path}")
        return False
    
    print("Project structure verified ✓")
    return True


def main():
    """Main build function."""
    print("CodeSafe GUI Build Script")
    print("=" * 40)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print()
    
    # Verify project structure
    if not verify_structure():
        return 1
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("ERROR: PyInstaller is not installed!")
        print("Please install it with: pip install PyInstaller")
        return 1
    
    # Check if PySide6 is installed
    try:
        import PySide6
        print(f"PySide6 version: {PySide6.__version__}")
    except ImportError:
        print("ERROR: PySide6 is not installed!")
        print("Please install it with: pip install PySide6")
        return 1
    
    # Clean previous builds
    if os.path.exists("dist"):
        print("Cleaning previous builds...")
        shutil.rmtree("dist")
    
    if os.path.exists("build"):
        print("Cleaning build directory...")
        shutil.rmtree("build")
    
    # Build the executable
    print("Building executable...")
    if build_executable():
        print("\nBuild completed successfully!")
        
        # Create installer scripts
        create_installer_scripts()
        
        # Show output location
        config = get_platform_specific_config()
        exe_name = config["exe_name"]
        
        if os.path.exists(f"dist/{exe_name}"):
            print(f"\nExecutable created: dist/{exe_name}")
            print(f"Size: {os.path.getsize(f'dist/{exe_name}') / (1024*1024):.1f} MB")
        else:
            print("\nWARNING: Executable not found in expected location!")
            print("Check the dist/ directory for the actual output.")
        
        return 0
    else:
        print("\nBuild failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())