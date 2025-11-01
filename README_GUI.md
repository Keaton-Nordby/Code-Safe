# CodeSafe GUI

A desktop GUI wrapper for the CodeSafe secret scanner, providing an intuitive interface for scanning codebases for secrets and vulnerabilities.

## Features

- **Easy Folder Selection**: Choose folders to scan via file dialog or drag & drop
- **Real-time Progress**: Visual progress bar and status updates during scanning
- **Comprehensive Results**: Table view with detector, file, line, severity, and remediation information
- **Export Options**: Save results as JSON or SARIF format
- **Configurable Scanning**: Adjust entropy threshold and exclude patterns
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Standalone Executables**: No Python installation required for end users

## Installation

### For Development

1. Install dependencies:
   ```bash
   pip install -r requirements-gui.txt
   ```

2. Run the GUI:
   ```bash
   python gui.py
   ```

### For End Users

Download the pre-built executable for your platform from the releases page, or build your own using the instructions below.

## Building Standalone Executables

### Prerequisites

- Python 3.10 or higher
- All dependencies installed (`pip install -r requirements-gui.txt`)

### Quick Build

Run the automated build script:

```bash
python build_gui.py
```

This will create platform-specific executables in the `dist/` directory:
- **Windows**: `CodeSafe.exe`
- **macOS**: `CodeSafe.app`
- **Linux**: `codesafe-gui`

### Manual Build

For more control, use PyInstaller directly:

#### Windows
```bash
pyinstaller --name CodeSafe --windowed --onefile --add-data "codesafe;codesafe" gui.py
```

#### macOS
```bash
pyinstaller --name CodeSafe --windowed --onedir --add-data "codesafe:codesafe" gui.py
```

#### Linux
```bash
pyinstaller --name codesafe-gui --windowed --onefile --add-data "codesafe:codesafe" gui.py
```

## Usage

### Basic Usage

1. **Launch the Application**: Double-click the executable or run `python gui.py`
2. **Select a Folder**: Click "Select Folder" or drag & drop a folder onto the interface
3. **Configure Options** (optional):
   - Adjust entropy threshold for high-entropy string detection
   - Set exclude patterns to skip certain directories
   - Enable dependency auditing for vulnerable packages
4. **Start Scan**: Click "Start Scan" to begin scanning
5. **View Results**: Results appear in the table as they're found
6. **Export Results**: Use the export buttons to save results as JSON or SARIF

### Advanced Configuration

- **Entropy Threshold**: Higher values (4.5+) reduce false positives but may miss some secrets
- **Exclude Patterns**: Use regex patterns to skip directories (e.g., `node_modules|\.git|dist`)
- **Dependency Audit**: Scans for vulnerable packages using pip-audit and npm audit

## File Structure

```
code-safe/
├── gui.py                 # Main GUI application
├── build_gui.py          # Build script for executables
├── requirements-gui.txt  # GUI-specific dependencies
├── codesafe/             # Scanner backend
│   ├── scanner.py
│   └── checks/
│       ├── patterns.py
│       ├── entropy.py
│       └── env_keys.py
└── dist/                 # Built executables (after building)
```

## Architecture

The GUI is built with PySide6 and follows a clean separation of concerns:

- **GUI Layer** (`gui.py`): User interface, event handling, and display logic
- **Scanner Backend** (`codesafe/`): Core scanning functionality (unchanged)
- **Worker Threads**: Background scanning to keep UI responsive
- **Export Integration**: Reuses existing JSON/SARIF export functions

## Troubleshooting

### Common Issues

1. **"No module named 'codesafe'"**: Make sure you're running from the project root directory
2. **GUI doesn't start**: Check that PySide6 is installed: `pip install PySide6`
3. **Build fails**: Ensure PyInstaller is installed: `pip install PyInstaller`
4. **Large executable size**: This is normal for PySide6 applications (50-100MB)

### Performance Tips

- Use exclude patterns to skip large directories like `node_modules`
- For very large codebases, consider running scans in smaller chunks
- The GUI shows progress, so you can cancel long-running scans if needed

## Development

### Adding New Features

1. **New Scanner Checks**: Add to `codesafe/checks/` and import in `gui.py`
2. **UI Improvements**: Modify the `CodeSafeGUI` class in `gui.py`
3. **Export Formats**: Add new export methods using existing scanner functions

### Testing

The GUI integrates directly with the existing scanner backend, so all scanner tests apply. For GUI-specific testing:

1. Test with various folder structures
2. Verify drag & drop functionality
3. Check export functionality with different result sets
4. Test on different platforms

## License

Same as the main CodeSafe project.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on your target platform
5. Submit a pull request

## Support

For issues specific to the GUI, please open an issue with:
- Your operating system and version
- Python version (if running from source)
- Steps to reproduce the issue
- Any error messages
