#!/usr/bin/env python3
"""
CodeSafe GUI - Desktop wrapper for the CodeSafe secret scanner.

This GUI provides a user-friendly interface for scanning codebases for secrets
and vulnerabilities using the existing CodeSafe scanner backend.
"""

import sys
import os
import json
import pathlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QProgressBar, QTableWidget, QTableWidgetItem,
    QFileDialog, QMessageBox, QTextEdit, QSplitter, QHeaderView,
    QGroupBox, QCheckBox, QSpinBox, QLineEdit, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QMimeData
from PySide6.QtGui import QFont, QDragEnterEvent, QDropEvent, QPixmap, QIcon

# Import scanner functions from the existing codesafe module
from codesafe.scanner import convert_to_sarif, preprocess_content, mask_secret
from codesafe.checks.patterns import scan_file_for_patterns
from codesafe.checks.entropy import scan_file_for_entropy, shannon_entropy, ENTROPY_THRESHOLD, MIN_LENGTH
from codesafe.checks.env_keys import scan_file_for_env_patterns


@dataclass
class ScanResult:
    """Data class for scan results."""
    detector: str
    file: str
    line: int
    severity: str
    remediation: str
    content: str
    type: str


class ScannerWorker(QThread):
    """Worker thread for running scans without blocking the GUI."""
    
    progress_updated = Signal(int, int)  # current, total
    result_found = Signal(ScanResult)
    scan_completed = Signal(list)  # list of ScanResult objects
    error_occurred = Signal(str)
    
    def __init__(self, root_path: str, exclude_patterns: str = "", 
                 entropy_threshold: float = 4.5, run_deps_audit: bool = False):
        super().__init__()
        self.root_path = root_path
        self.exclude_patterns = exclude_patterns
        self.entropy_threshold = entropy_threshold
        self.run_deps_audit = run_deps_audit
        self._cancelled = False
    
    def cancel(self):
        """Cancel the current scan."""
        self._cancelled = True
    
    def run(self):
        """Run the scan in a separate thread."""
        try:
            findings = self._run_scan()
            self.scan_completed.emit(findings)
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def _run_scan(self) -> List[ScanResult]:
        """Run the actual scan using the existing scanner logic."""
        findings = []
        total_files = 0
        processed_files = 0
        
        # Count total files first
        for root_dir, dirs, files in os.walk(self.root_path):
            # Skip common folders
            skip_dirs = {"node_modules", ".git", "dist", "build", ".venv", "venv", ".tox", "target", ".idea", ".vscode"}
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if self._should_skip_file(os.path.join(root_dir, file)):
                    continue
                total_files += 1
        
        # Now scan files
        for root_dir, dirs, files in os.walk(self.root_path):
            if self._cancelled:
                break
                
            # Skip common folders
            skip_dirs = {"node_modules", ".git", "dist", "build", ".venv", "venv", ".tox", "target", ".idea", ".vscode"}
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if self._cancelled:
                    break
                    
                file_path = os.path.join(root_dir, file)
                
                if self._should_skip_file(file_path):
                    continue
                
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        raw_content = f.read()
                    
                    # Preprocess content using existing function
                    content = preprocess_content(raw_content)
                    
                    # Run all checks using existing functions
                    pattern_findings = scan_file_for_patterns(file_path, content)
                    entropy_findings = scan_file_for_entropy(file_path, content)
                    env_findings = scan_file_for_env_patterns(file_path, content)
                    
                    # Convert to ScanResult objects
                    for f in pattern_findings:
                        result = ScanResult(
                            detector="Pattern Match",
                            file=f["file"],
                            line=f["line"],
                            severity="HIGH",
                            remediation="Remove secret from code, rotate it, and load from a secure store.",
                            content=f["content"],
                            type="pattern"
                        )
                        findings.append(result)
                        self.result_found.emit(result)
                    
                    for f in entropy_findings:
                        result = ScanResult(
                            detector="High Entropy",
                            file=f["file"],
                            line=f["line"],
                            severity="MEDIUM",
                            remediation="Review this string; if it is a secret, remove and rotate it.",
                            content=f["content"],
                            type="entropy"
                        )
                        findings.append(result)
                        self.result_found.emit(result)
                    
                    for f in env_findings:
                        result = ScanResult(
                            detector="Environment Variable",
                            file=f["file"],
                            line=f["line"],
                            severity="MEDIUM",
                            remediation="Don't hardcode secrets. Use environment variables or a secrets manager.",
                            content=f["content"],
                            type="env"
                        )
                        findings.append(result)
                        self.result_found.emit(result)
                
                except Exception:
                    pass  # Skip unreadable files
                
                processed_files += 1
                self.progress_updated.emit(processed_files, total_files)
        
        return findings
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped based on exclude patterns."""
        if not self.exclude_patterns:
            return False
        
        import re
        try:
            exclude_regex = re.compile(self.exclude_patterns)
            return bool(exclude_regex.search(file_path))
        except re.error:
            return False


class CodeSafeGUI(QMainWindow):
    """Main GUI window for CodeSafe scanner."""
    
    def __init__(self):
        super().__init__()
        self.scanner_worker = None
        self.current_results = []
        self.scan_folder = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("CodeSafe - Secret Scanner")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - Controls
        left_panel = self._create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self._create_results_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([300, 900])
        
        # Status bar
        self.statusBar().showMessage("Ready to scan")
    
    def _create_control_panel(self) -> QWidget:
        """Create the left control panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # File selection group
        file_group = QGroupBox("Scan Target")
        file_layout = QVBoxLayout(file_group)
        
        # Folder selection
        self.folder_label = QLabel("No folder selected")
        self.folder_label.setWordWrap(True)
        self.folder_label.setStyleSheet("QLabel { border: 2px dashed #ccc; padding: 10px; }")
        self.folder_label.setAlignment(Qt.AlignCenter)
        self.folder_label.setMinimumHeight(80)
        file_layout.addWidget(self.folder_label)
        
        # Folder selection buttons
        button_layout = QHBoxLayout()
        self.select_folder_btn = QPushButton("Select Folder")
        self.select_folder_btn.clicked.connect(self.select_folder)
        self.clear_folder_btn = QPushButton("Clear")
        self.clear_folder_btn.clicked.connect(self.clear_folder)
        self.clear_folder_btn.setEnabled(False)
        
        button_layout.addWidget(self.select_folder_btn)
        button_layout.addWidget(self.clear_folder_btn)
        file_layout.addLayout(button_layout)
        
        # Enable drag and drop
        self.folder_label.setAcceptDrops(True)
        self.folder_label.dragEnterEvent = self.drag_enter_event
        self.folder_label.dropEvent = self.drop_event
        
        layout.addWidget(file_group)
        
        # Scan options group
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        # Entropy threshold
        entropy_layout = QHBoxLayout()
        entropy_layout.addWidget(QLabel("Entropy Threshold:"))
        self.entropy_spinbox = QSpinBox()
        self.entropy_spinbox.setRange(10, 100)  # 1.0 to 10.0 with 0.1 precision
        self.entropy_spinbox.setValue(45)  # 4.5 * 10 for integer precision
        self.entropy_spinbox.setSuffix(".0")
        entropy_layout.addWidget(self.entropy_spinbox)
        entropy_layout.addStretch()
        options_layout.addLayout(entropy_layout)
        
        # Exclude patterns
        exclude_layout = QVBoxLayout()
        exclude_layout.addWidget(QLabel("Exclude Patterns (regex):"))
        self.exclude_edit = QLineEdit()
        self.exclude_edit.setPlaceholderText(r"node_modules|\.git|dist|build")
        self.exclude_edit.setText(r"node_modules|\.git|dist|build|\.venv|venv|\.tox|target|\.idea|\.vscode")

        exclude_layout.addWidget(self.exclude_edit)
        options_layout.addLayout(exclude_layout)
        
        # Dependency audit checkbox
        self.deps_audit_cb = QCheckBox("Run dependency audit")
        self.deps_audit_cb.setToolTip("Check for vulnerable dependencies (requires pip-audit/npm)")
        options_layout.addWidget(self.deps_audit_cb)
        
        layout.addWidget(options_group)
        
        # Scan controls group
        scan_group = QGroupBox("Scan Controls")
        scan_layout = QVBoxLayout(scan_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        scan_layout.addWidget(self.progress_bar)
        
        # Scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setEnabled(False)
        scan_layout.addWidget(self.scan_btn)
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.cancel_btn.setEnabled(False)
        scan_layout.addWidget(self.cancel_btn)
        
        layout.addWidget(scan_group)
        
        # Export group
        export_group = QGroupBox("Export Results")
        export_layout = QVBoxLayout(export_group)
        
        self.export_json_btn = QPushButton("Export as JSON")
        self.export_json_btn.clicked.connect(self.export_json)
        self.export_json_btn.setEnabled(False)
        export_layout.addWidget(self.export_json_btn)
        
        self.export_sarif_btn = QPushButton("Export as SARIF")
        self.export_sarif_btn.clicked.connect(self.export_sarif)
        self.export_sarif_btn.setEnabled(False)
        export_layout.addWidget(self.export_sarif_btn)
        
        layout.addWidget(export_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        return panel
    
    def _create_results_panel(self) -> QWidget:
        """Create the right results panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Results header
        header_layout = QHBoxLayout()
        self.results_label = QLabel("Scan Results")
        self.results_label.setFont(QFont("Arial", 12, QFont.Bold))
        header_layout.addWidget(self.results_label)
        header_layout.addStretch()
        
        # Clear results button
        self.clear_results_btn = QPushButton("Clear Results")
        self.clear_results_btn.clicked.connect(self.clear_results)
        self.clear_results_btn.setEnabled(False)
        header_layout.addWidget(self.clear_results_btn)
        
        layout.addLayout(header_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Detector", "File", "Line", "Severity", "Remediation", "Content"
        ])
        
        # Configure table
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Detector
        header.setSectionResizeMode(1, QHeaderView.Stretch)          # File
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents) # Line
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents) # Severity
        header.setSectionResizeMode(4, QHeaderView.Stretch)          # Remediation
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents) # Content
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        layout.addWidget(self.results_table)
        
        return panel
    
    def drag_enter_event(self, event: QDragEnterEvent):
        """Handle drag enter event."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def drop_event(self, event: QDropEvent):
        """Handle drop event."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].isLocalFile():
                path = urls[0].toLocalFile()
                if os.path.isdir(path):
                    self.set_scan_folder(path)
            event.acceptProposedAction()
    
    def select_folder(self):
        """Open folder selection dialog."""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.set_scan_folder(folder)
    
    def set_scan_folder(self, folder_path: str):
        """Set the folder to scan."""
        self.scan_folder = folder_path
        self.folder_label.setText(f"📁 {folder_path}")
        self.folder_label.setStyleSheet("QLabel { border: 2px solid #4CAF50; padding: 10px; background-color: #f0f8f0; }")
        self.scan_btn.setEnabled(True)
        self.clear_folder_btn.setEnabled(True)
        self.statusBar().showMessage(f"Ready to scan: {folder_path}")
    
    def clear_folder(self):
        """Clear the selected folder."""
        self.scan_folder = None
        self.folder_label.setText("No folder selected")
        self.folder_label.setStyleSheet("QLabel { border: 2px dashed #ccc; padding: 10px; }")
        self.scan_btn.setEnabled(False)
        self.clear_folder_btn.setEnabled(False)
        self.statusBar().showMessage("Ready to scan")
    
    def start_scan(self):
        """Start the scanning process."""
        if not self.scan_folder:
            return
        
        # Clear previous results
        self.clear_results()
        
        # Get scan options
        entropy_threshold = self.entropy_spinbox.value() / 10.0
        exclude_patterns = self.exclude_edit.text().strip()
        run_deps_audit = self.deps_audit_cb.isChecked()
        
        # Update UI
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Start scanner worker
        self.scanner_worker = ScannerWorker(
            self.scan_folder, 
            exclude_patterns, 
            entropy_threshold, 
            run_deps_audit
        )
        self.scanner_worker.progress_updated.connect(self.update_progress)
        self.scanner_worker.result_found.connect(self.add_result)
        self.scanner_worker.scan_completed.connect(self.scan_completed)
        self.scanner_worker.error_occurred.connect(self.scan_error)
        self.scanner_worker.start()
        
        self.statusBar().showMessage("Scanning in progress...")
    
    def cancel_scan(self):
        """Cancel the current scan."""
        if self.scanner_worker:
            self.scanner_worker.cancel()
            self.scanner_worker.wait()
            self.scanner_worker = None
        
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage("Scan cancelled")
    
    def update_progress(self, current: int, total: int):
        """Update progress bar."""
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
            self.statusBar().showMessage(f"Scanning... {current}/{total} files")
    
    def add_result(self, result: ScanResult):
        """Add a single result to the table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Set items
        self.results_table.setItem(row, 0, QTableWidgetItem(result.detector))
        self.results_table.setItem(row, 1, QTableWidgetItem(result.file))
        self.results_table.setItem(row, 2, QTableWidgetItem(str(result.line)))
        
        # Severity with color coding
        severity_item = QTableWidgetItem(result.severity)
        if result.severity == "HIGH":
            severity_item.setBackground(Qt.red)
        elif result.severity == "MEDIUM":
            severity_item.setBackground(Qt.yellow)
        self.results_table.setItem(row, 3, severity_item)
        
        self.results_table.setItem(row, 4, QTableWidgetItem(result.remediation))
        
        # Mask content for security using existing function
        masked_content = mask_secret(result.content)
        self.results_table.setItem(row, 5, QTableWidgetItem(masked_content))
        
        # Store result
        self.current_results.append(result)
    
    def scan_completed(self, results: List[ScanResult]):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        count = len(results)
        if count > 0:
            self.statusBar().showMessage(f"Scan completed - {count} findings")
            self.export_json_btn.setEnabled(True)
            self.export_sarif_btn.setEnabled(True)
            self.clear_results_btn.setEnabled(True)
        else:
            self.statusBar().showMessage("Scan completed - No findings")
        
        # Show completion message
        QMessageBox.information(self, "Scan Complete", 
                               f"Scan completed with {count} findings.")
    
    def scan_error(self, error_msg: str):
        """Handle scan error."""
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage("Scan error occurred")
        
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scanning:\n{error_msg}")
    
    def clear_results(self):
        """Clear all results."""
        self.results_table.setRowCount(0)
        self.current_results.clear()
        self.export_json_btn.setEnabled(False)
        self.export_sarif_btn.setEnabled(False)
        self.clear_results_btn.setEnabled(False)
        self.statusBar().showMessage("Results cleared")
    
    def export_json(self):
        """Export results as JSON."""
        if not self.current_results:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "codesafe_results.json", "JSON Files (*.json)"
        )
        if filename:
            try:
                # Convert to dict format compatible with existing scanner
                data = []
                for result in self.current_results:
                    data.append({
                        "file": result.file,
                        "line": result.line,
                        "content": result.content,
                        "type": result.type,
                        "severity": result.severity.lower()
                    })
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export JSON:\n{str(e)}")
    
    def export_sarif(self):
        """Export results as SARIF."""
        if not self.current_results:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export SARIF", "codesafe_results.sarif", "SARIF Files (*.sarif)"
        )
        if filename:
            try:
                # Convert to format expected by convert_to_sarif
                findings_data = []
                for result in self.current_results:
                    findings_data.append({
                        "file": result.file,
                        "line": result.line,
                        "content": result.content,
                        "type": result.type,
                        "severity": result.severity.lower()
                    })
                
                sarif_data = convert_to_sarif(findings_data)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(sarif_data, f, indent=2)
                
                QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export SARIF:\n{str(e)}")


def main():
    """Main entry point for the GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("CodeSafe")
    app.setApplicationVersion("1.0.0")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = CodeSafeGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()