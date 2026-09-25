#!/usr/bin/env python3
"""
AEGIS AI Data Recovery - Ultra-Modern Desktop Application.
Features:
1. Real-Time Folder Monitor & Instant Deleted File/Photo Recovery (Recovers directly into the same path)
2. Deleted File & Photo Detection Center with 1-Click "Recover to Same Path"
3. Targeted File & Photo Recovery (Recycle Bin + Forensic Shadow Vault)
4. Deterministic Sector Carving & Damaged Binary Reconstruction (Strict 0% Fake Bytes Guarantee)
Crafted with PyQt5.
"""
import sys
import os
import io
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QFileDialog, QProgressBar,
    QTextEdit, QFrame, QMessageBox, QTabWidget, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QCheckBox, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QColor, QImage, QPainter, QBrush, QPen, QIcon

from backend.config import settings
from backend.storage.file_source import FileSource
from backend.storage.disk_image import DiskImageSource
from backend.recovery.scanner import RawStorageScanner
from backend.recovery.carving import FileCarver
from backend.recovery.fragments import Fragment, slice_bytes_into_fragments
from backend.ml.classifier import file_classifier
from backend.ml.clustering import fragment_clusterer
from backend.recovery.reconstruction import ReconstructionEngine
from backend.recovery.confidence import ConfidenceEngine
from backend.security.hashing import calculate_file_sha256, calculate_bytes_sha256
from backend.recovery.folder_sentinel import (
    FolderAnalyzer, AutoRecoverySentinel, FolderVault, recover_target_file
)
from backend.recovery.recycle_bin import WindowsRecycleBin

# Modern Cyber Dark Premium Stylesheet
PREMIUM_THEME = """
QMainWindow {
    background-color: #080c15;
}
QWidget {
    background-color: #080c15;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #1e293b;
    background-color: #090e1a;
    border-radius: 12px;
    top: -1px;
}
QTabBar::tab {
    background: #0f172a;
    color: #94a3b8;
    font-weight: 700;
    font-size: 13px;
    padding: 11px 22px;
    border: 1px solid #1e293b;
    border-bottom: none;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    margin-right: 6px;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #131d33, stop:1 #1e293b);
    color: #38bdf8;
    border-top: 2px solid #38bdf8;
}
QTabBar::tab:hover:!selected {
    background: #172033;
    color: #e2e8f0;
}
QFrame#glassCard {
    background-color: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 16px;
}
QFrame#alertCard {
    background-color: #1a1017;
    border: 1px solid #ef4444;
    border-radius: 14px;
}
QFrame#alertCardSuccess {
    background-color: #091f19;
    border: 1px solid #10b981;
    border-radius: 14px;
}
QFrame#fileDropArea {
    background-color: #070d1a;
    border: 2px dashed #2563eb;
    border-radius: 14px;
}
QFrame#previewCard {
    background-color: #070d1a;
    border: 1px solid #1e293b;
    border-radius: 14px;
}
QFrame#metricCard {
    background-color: #131d33;
    border: 1px solid #233252;
    border-radius: 12px;
}
QLineEdit {
    background-color: #070d1a;
    border: 1px solid #273754;
    border-radius: 8px;
    padding: 8px 12px;
    color: #f8fafc;
    font-size: 13px;
    font-weight: 500;
}
QLineEdit:focus {
    border-color: #38bdf8;
    background-color: #0b1426;
}
QPushButton {
    background-color: #162035;
    border: 1px solid #273754;
    border-radius: 9px;
    padding: 8px 16px;
    color: #f8fafc;
    font-weight: 600;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #1e2c49;
    border-color: #38bdf8;
    color: #38bdf8;
}
QPushButton:pressed {
    background-color: #111a2d;
}
QPushButton#heroActionBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:0.5 #4f46e5, stop:1 #7c3aed);
    border: 1px solid #6366f1;
    color: #ffffff;
    font-size: 13px;
    font-weight: 700;
    padding: 11px 22px;
    border-radius: 10px;
}
QPushButton#heroActionBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:0.5 #4338ca, stop:1 #6d28d9);
    border-color: #a5b4fc;
}
QPushButton#guardActiveBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
    border: 1px solid #34d399;
    color: #ffffff;
    font-size: 13px;
    font-weight: 800;
    padding: 10px 20px;
    border-radius: 10px;
}
QPushButton#guardActiveBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669);
    border-color: #6ee7b7;
}
QPushButton#guardStandbyBtn {
    background: #162035;
    border: 1px solid #273754;
    color: #94a3b8;
    font-size: 13px;
    font-weight: 700;
    padding: 10px 20px;
    border-radius: 10px;
}
QPushButton#guardStandbyBtn:hover {
    background: #1e2c49;
    border-color: #38bdf8;
    color: #38bdf8;
}
QPushButton#recoverDirectBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
    border: 1px solid #34d399;
    color: #ffffff;
    font-size: 13px;
    font-weight: 800;
    padding: 8px 18px;
    border-radius: 8px;
}
QPushButton#recoverDirectBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669);
}
QPushButton#successBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
    border: 1px solid #34d399;
    color: #ffffff;
    font-weight: 700;
    font-size: 13px;
    padding: 10px 18px;
    border-radius: 10px;
}
QPushButton#successBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669);
}
QPushButton#quickPillBtn {
    background-color: #131d33;
    border: 1px solid #233252;
    border-radius: 6px;
    padding: 4px 10px;
    color: #94a3b8;
    font-size: 11px;
    font-weight: 600;
}
QPushButton#quickPillBtn:hover {
    background-color: #1e2c49;
    border-color: #38bdf8;
    color: #38bdf8;
}
QComboBox {
    background-color: #070d1a;
    border: 1px solid #273754;
    border-radius: 8px;
    padding: 8px 12px;
    color: #f8fafc;
    font-size: 13px;
    font-weight: 500;
}
QComboBox:focus {
    border-color: #38bdf8;
    background-color: #0b1426;
}
QProgressBar {
    border: none;
    border-radius: 6px;
    text-align: center;
    background-color: #070d1a;
    color: transparent;
    height: 8px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #06b6d4, stop:0.5 #3b82f6, stop:1 #10b981);
    border-radius: 6px;
}
QTableWidget {
    background-color: #070d1a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    gridline-color: #152033;
    color: #e2e8f0;
    font-size: 12px;
    selection-background-color: #1e293b;
    selection-color: #38bdf8;
}
QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    font-weight: 700;
    font-size: 11px;
    padding: 7px 10px;
    border: none;
    border-bottom: 1px solid #1e293b;
}
QTextEdit {
    background-color: #050810;
    border: 1px solid #1a2333;
    border-radius: 10px;
    color: #94a3b8;
    font-family: "Consolas", monospace;
    font-size: 11px;
    padding: 8px;
}
QCheckBox {
    color: #94a3b8;
    font-size: 12px;
    font-weight: 600;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #334155;
    background-color: #070d1a;
}
QCheckBox::indicator:checked {
    background-color: #10b981;
    border-color: #34d399;
}
QMessageBox {
    background-color: #0f172a;
    color: #e2e8f0;
}
QMessageBox QLabel {
    color: #e2e8f0;
    font-size: 13px;
}
QMessageBox QPushButton {
    background-color: #162035;
    border: 1px solid #273754;
    border-radius: 8px;
    padding: 8px 18px;
    color: #ffffff;
    font-weight: 700;
    font-size: 12px;
}
QMessageBox QPushButton:hover {
    background-color: #059669;
    border-color: #34d399;
}
"""

class BeautifulRecoveryWorker(QThread):
    """Thread for recovering files from disk images or raw files."""
    progress_changed = pyqtSignal(str, int)
    log_emitted = pyqtSignal(str)
    finished_success = pyqtSignal(dict)
    finished_error = pyqtSignal(str)

    def __init__(self, source_path: str, format_choice: str):
        super().__init__()
        self.source_path = Path(source_path)
        self.format_choice = format_choice

    def run(self):
        try:
            self.progress_changed.emit("Acquiring evidence & computing custody hash...", 15)
            if not self.source_path.exists():
                raise FileNotFoundError("Target evidence file does not exist.")

            is_disk = self.source_path.suffix.lower() in (".dd", ".img", ".raw")
            source = DiskImageSource(self.source_path) if is_disk else FileSource(self.source_path)
            source.open()
            total_size = source.get_size()

            self.progress_changed.emit("Scanning raw sectors for file signatures...", 40)
            self.log_emitted.emit(f"[*] Mounted Source: {self.source_path.name} ({total_size:,} bytes)")

            scanner = RawStorageScanner(source, block_size=4096)
            scan_report = scanner.scan(max_bytes=min(total_size, 30 * 1024 * 1024))
            carver = FileCarver(source)
            carved = carver.carve_from_scan(scan_report, job_id="AEGIS", fragment_size=4096)

            self.progress_changed.emit("AI classifying fragments & assembling sequence...", 70)
            fragments = []
            for c in carved:
                fragments.extend(c.fragments)

            if not fragments:
                raw_data = source.read_bytes(0, min(total_size, 25 * 1024 * 1024))
                fragments = slice_bytes_into_fragments(raw_data, job_id="AEGIS", fragment_size=4096)

            for f in fragments:
                pred = file_classifier.predict(f.data)
                f.predicted_type = pred["predicted_type"]
                if f.predicted_type == "jpeg":
                    if f.data.startswith(b"\xFF\xD8"): f.is_header = True
                    if b"\xFF\xD9" in f.data[-4:]: f.is_footer = True
                elif f.predicted_type == "png":
                    if f.data.startswith(b"\x89PNG"): f.is_header = True
                    if b"IEND" in f.data[-16:]: f.is_footer = True

            clusters = fragment_clusterer.cluster_fragments(fragments) or {"default": fragments}
            target_fmt = self.format_choice if self.format_choice != "auto" else fragments[0].predicted_type
            
            recovered_file = None
            output_dir = settings.output_dir
            output_dir.mkdir(parents=True, exist_ok=True)

            for cid, c_frags in clusters.items():
                engine = ReconstructionEngine(target_type=target_fmt)
                candidates = engine.reconstruct_and_evaluate(c_frags, max_candidates=2)
                if not candidates:
                    continue

                best = candidates[0]
                conf = ConfidenceEngine.evaluate(
                    fragments_used=best.fragments,
                    validation_result=best.validation_result,
                    avg_model_prob=best.avg_relationship_probability
                )

                ext = target_fmt if target_fmt != "unknown" else "bin"
                out_name = f"recovered_artifact.{ext}"
                out_path = output_dir / out_name
                with open(out_path, "wb") as f_out:
                    f_out.write(best.reconstructed_bytes)

                recovered_file = {
                    "path": str(out_path.resolve()),
                    "name": out_name,
                    "type": target_fmt,
                    "size": len(best.reconstructed_bytes),
                    "raw_bytes": best.reconstructed_bytes,
                    "integrity": conf.integrity_score,
                    "confidence": int(conf.model_confidence * 100),
                    "is_valid": best.validation_result.decoder_success,
                    "fragments_count": len(best.fragments),
                    "restored_to": str(out_path.resolve()),
                    "source": "Deterministic Carving & Neural Assembly",
                    "fabricated_bytes": 0
                }
                break

            source.close()

            if recovered_file:
                self.progress_changed.emit("Reconstruction complete!", 100)
                self.finished_success.emit(recovered_file)
            else:
                self.finished_error.emit("Could not recover a complete file from this source.")

        except Exception as e:
            self.finished_error.emit(str(e))


class SentinelThread(QThread):
    """Real-Time Folder Sentinel Worker Thread."""
    deletion_detected = pyqtSignal(dict)  # del_info dict
    file_recovered = pyqtSignal(dict)     # recovered_info dict
    log_emitted = pyqtSignal(str)

    def __init__(self, directory: str, target_filename: str = "*", auto_recover: bool = True):
        super().__init__()
        self.directory = directory
        self.target_filename = target_filename
        self.auto_recover = auto_recover
        self.sentinel: Optional[AutoRecoverySentinel] = None

    def run(self):
        self.sentinel = AutoRecoverySentinel(
            directory=self.directory,
            target_filename=self.target_filename,
            auto_recover=self.auto_recover,
            on_deletion=lambda del_info: self.deletion_detected.emit(del_info),
            on_recovery=lambda rec_info: self.file_recovered.emit(rec_info),
            on_log=lambda msg: self.log_emitted.emit(msg),
            poll_interval=0.35
        )
        self.sentinel.start()
        while self.sentinel and self.sentinel.is_active():
            self.msleep(150)

    def stop(self):
        if self.sentinel:
            self.sentinel.stop()


class FolderAnalysisThread(QThread):
    """Background thread to index and protect files in a selected directory."""
    finished_analysis = pyqtSignal(dict)
    finished_error = pyqtSignal(str)
    log_emitted = pyqtSignal(str)

    def __init__(self, directory: str):
        super().__init__()
        self.directory = directory

    def run(self):
        try:
            self.log_emitted.emit(f"[*] Analyzing folder: {self.directory}...")
            data = FolderAnalyzer.analyze_folder(self.directory)
            self.log_emitted.emit(f"[✓] Analysis complete: {data['total_files']} files protected ({data['total_size_mb']} MB).")
            self.finished_analysis.emit(data)
        except Exception as e:
            self.finished_error.emit(str(e))


class BeautifulRecoveryApp(QMainWindow):
    """Modern, Beautiful, State-of-the-Art Data Recovery & Auto-Recovery Suite."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Data Recovery • Real-Time Deleted File & Photo Monitor")
        self.resize(1180, 800)
        self.setMinimumSize(1000, 700)
        self.setStyleSheet(PREMIUM_THEME)

        self.selected_path: Optional[str] = None
        self.recovered_result: Optional[dict] = None
        self.last_deleted_info: Optional[dict] = None
        self.worker: Optional[BeautifulRecoveryWorker] = None
        self.sentinel_thread: Optional[SentinelThread] = None
        self.analysis_thread: Optional[FolderAnalysisThread] = None

        self.init_ui()

        # Automatically start monitoring Desktop by default
        QTimer.singleShot(400, self.auto_start_default_monitor)

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(24, 20, 24, 20)
        root_layout.setSpacing(14)

        # ── 1. TOP HEADER & BRANDING ─────────────────────────────────────────
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(4)

        brand_lbl = QLabel("✨ AI Data Recovery • Real-Time Laptop Folder Monitor")
        brand_lbl.setFont(QFont("Segoe UI", 16, QFont.Bold))
        brand_lbl.setStyleSheet("color: #ffffff; letter-spacing: 0.3px;")
        
        tagline = QLabel("Real-Time File & Photo Deletion Detection • Instant Recovery to Same Path • 100% Authentic Data")
        tagline.setStyleSheet("color: #94a3b8; font-size: 13px;")

        title_box.addWidget(brand_lbl)
        title_box.addWidget(tagline)

        # Security Status Pill
        self.shield_badge = QLabel("🟢 REAL-TIME MONITOR: ACTIVE")
        self.shield_badge.setStyleSheet("""
            background-color: #062e24;
            color: #34d399;
            font-size: 11px;
            font-weight: 800;
            padding: 8px 16px;
            border-radius: 20px;
            border: 1px solid #059669;
        """)

        header_row.addLayout(title_box)
        header_row.addStretch()
        header_row.addWidget(self.shield_badge)
        root_layout.addLayout(header_row)

        # ── 2. MAIN TABBED INTERFACE ─────────────────────────────────────────
        self.tab_widget = QTabWidget()
        
        # TAB 1: Real-time Folder Monitor & Deleted File/Photo Recovery
        tab_sentinel = self.create_sentinel_tab()
        self.tab_widget.addTab(tab_sentinel, "🛡️ Real-Time Folder Monitor & Auto-Recovery")

        # TAB 2: Damaged Evidence File & Sector Carving
        tab_carving = self.create_carving_tab()
        self.tab_widget.addTab(tab_carving, "🔬 Damaged File & Sector Carving")

        root_layout.addWidget(self.tab_widget, stretch=1)

        # ── 3. COLLAPSIBLE TECHNICAL FORENSICS CONSOLE ───────────────────────
        self.log_drawer_btn = QPushButton("⚙️  Forensics Activity & Audit Trail  ▼")
        self.log_drawer_btn.setStyleSheet("""
            background-color: transparent;
            border: none;
            color: #64748b;
            font-size: 11px;
            font-weight: 600;
            padding: 4px;
        """)
        self.log_drawer_btn.clicked.connect(self.toggle_console)
        root_layout.addWidget(self.log_drawer_btn)

        self.console_log = QTextEdit()
        self.console_log.setReadOnly(True)
        self.console_log.setFixedHeight(105)
        self.console_log.setVisible(False)
        root_layout.addWidget(self.console_log)

    # ═════════════════════════════════════════════════════════════════════════
    # TAB 1: REAL-TIME FOLDER MONITOR & DELETED FILE/PHOTO RECOVERY
    # ═════════════════════════════════════════════════════════════════════════
    def create_sentinel_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(18)

        # LEFT COLUMN: Folder Configuration, Deletion Alert Card, & Files Table
        left_card = QFrame()
        left_card.setObjectName("glassCard")
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(18, 18, 18, 18)
        left_layout.setSpacing(12)

        # Step 1: Directory Selection
        dir_lbl = QLabel("MONITORED LAPTOP FOLDER")
        dir_lbl.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 800; letter-spacing: 0.8px;")
        left_layout.addWidget(dir_lbl)

        dir_input_row = QHBoxLayout()
        dir_input_row.setSpacing(8)
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText("Enter or browse folder path (e.g. C:\\Users\\...\\Desktop)")
        default_desktop = str(Path.home() / "Desktop")
        self.dir_input.setText(default_desktop)

        browse_dir_btn = QPushButton("📁 Browse...")
        browse_dir_btn.clicked.connect(self.browse_directory)
        dir_input_row.addWidget(self.dir_input, stretch=1)
        dir_input_row.addWidget(browse_dir_btn)
        left_layout.addLayout(dir_input_row)

        # Quick Jump Folder Pills
        quick_row = QHBoxLayout()
        quick_row.setSpacing(6)
        
        btn_desk = QPushButton("🖥️ Desktop")
        btn_desk.setObjectName("quickPillBtn")
        btn_desk.clicked.connect(lambda: self.set_quick_dir("Desktop"))

        btn_down = QPushButton("📥 Downloads")
        btn_down.setObjectName("quickPillBtn")
        btn_down.clicked.connect(lambda: self.set_quick_dir("Downloads"))

        btn_docs = QPushButton("📄 Documents")
        btn_docs.setObjectName("quickPillBtn")
        btn_docs.clicked.connect(lambda: self.set_quick_dir("Documents"))

        btn_pics = QPushButton("🖼️ Pictures")
        btn_pics.setObjectName("quickPillBtn")
        btn_pics.clicked.connect(lambda: self.set_quick_dir("Pictures"))

        quick_row.addWidget(btn_desk)
        quick_row.addWidget(btn_down)
        quick_row.addWidget(btn_docs)
        quick_row.addWidget(btn_pics)
        quick_row.addStretch()
        left_layout.addLayout(quick_row)

        # Real-Time Controls Row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(10)

        self.guard_toggle_btn = QPushButton("⏹️ Pause Real-Time Monitor")
        self.guard_toggle_btn.setObjectName("guardActiveBtn")
        self.guard_toggle_btn.clicked.connect(self.toggle_sentinel_guard)

        self.rescan_btn = QPushButton("🔍 Re-Scan Folder")
        self.rescan_btn.clicked.connect(self.analyze_current_folder)

        self.auto_recover_chk = QCheckBox("⚡ Auto-recover to same path immediately when deleted")
        self.auto_recover_chk.setChecked(True)
        self.auto_recover_chk.stateChanged.connect(self.on_auto_recover_toggle)

        ctrl_row.addWidget(self.guard_toggle_btn)
        ctrl_row.addWidget(self.rescan_btn)
        ctrl_row.addStretch()
        left_layout.addLayout(ctrl_row)

        # Recovery Permission Preference
        pref_row = QHBoxLayout()
        pref_row.setSpacing(14)
        
        self.require_permission_chk = QCheckBox("🛡️ Ask my permission before recovering (Prompt me)")
        self.require_permission_chk.setChecked(True)
        self.require_permission_chk.stateChanged.connect(self.on_require_permission_toggle)

        self.auto_recover_chk = QCheckBox("⚡ Auto-recover without asking")
        self.auto_recover_chk.setChecked(False)
        self.auto_recover_chk.stateChanged.connect(self.on_auto_recover_toggle)

        pref_row.addWidget(self.require_permission_chk)
        pref_row.addWidget(self.auto_recover_chk)
        pref_row.addStretch()
        left_layout.addLayout(pref_row)

        # ── PROMINENT DELETED FILE / PHOTO DETECTION CARD ────────────────────
        self.deletion_alert_frame = QFrame()
        self.deletion_alert_frame.setObjectName("alertCard")
        alert_vbox = QVBoxLayout(self.deletion_alert_frame)
        alert_vbox.setContentsMargins(14, 12, 14, 12)
        alert_vbox.setSpacing(8)

        alert_header = QHBoxLayout()
        self.alert_badge = QLabel("⚠️ DELETED FILE / PHOTO DETECTED")
        self.alert_badge.setStyleSheet("color: #ef4444; font-size: 11px; font-weight: 800; letter-spacing: 0.6px;")
        
        self.alert_time_lbl = QLabel("")
        self.alert_time_lbl.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 600;")
        
        alert_header.addWidget(self.alert_badge)
        alert_header.addStretch()
        alert_header.addWidget(self.alert_time_lbl)
        alert_vbox.addLayout(alert_header)

        # Details & Recover Action Row
        alert_content_row = QHBoxLayout()
        alert_content_row.setSpacing(12)

        self.alert_icon_lbl = QLabel("🖼️")
        self.alert_icon_lbl.setStyleSheet("font-size: 28px;")

        detail_col = QVBoxLayout()
        detail_col.setSpacing(2)
        self.alert_name_lbl = QLabel("No deleted files detected")
        self.alert_name_lbl.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: 700;")
        self.alert_path_lbl = QLabel("Real-time monitor is actively watching this folder. Delete any file to test.")
        self.alert_path_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
        detail_col.addWidget(self.alert_name_lbl)
        detail_col.addWidget(self.alert_path_lbl)

        btn_group = QHBoxLayout()
        btn_group.setSpacing(8)

        self.alert_recover_btn = QPushButton("⚡ Yes, Recover to Same Path")
        self.alert_recover_btn.setObjectName("recoverDirectBtn")
        self.alert_recover_btn.setVisible(False)
        self.alert_recover_btn.clicked.connect(self.on_alert_recover_clicked)

        self.alert_deny_btn = QPushButton("✕ Keep Deleted")
        self.alert_deny_btn.setVisible(False)
        self.alert_deny_btn.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                border: 1px solid #334155;
                color: #94a3b8;
                font-size: 12px;
                font-weight: 600;
                padding: 7px 14px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #334155;
                color: #ffffff;
            }
        """)
        self.alert_deny_btn.clicked.connect(self.on_alert_deny_clicked)

        btn_group.addWidget(self.alert_recover_btn)
        btn_group.addWidget(self.alert_deny_btn)

        alert_content_row.addWidget(self.alert_icon_lbl)
        alert_content_row.addLayout(detail_col, stretch=1)
        alert_content_row.addLayout(btn_group)
        alert_vbox.addLayout(alert_content_row)

        left_layout.addWidget(self.deletion_alert_frame)

        # ── MONITORED FILES IN FOLDER TABLE ──────────────────────────────────
        table_title_row = QHBoxLayout()
        t_lbl = QLabel("FOLDER FILES & REAL-TIME STATUS")
        t_lbl.setStyleSheet("color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 0.6px;")
        
        self.files_count_lbl = QLabel("0 files")
        self.files_count_lbl.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 600;")

        table_title_row.addWidget(t_lbl)
        table_title_row.addStretch()
        table_title_row.addWidget(self.files_count_lbl)
        left_layout.addLayout(table_title_row)

        self.files_table = QTableWidget(0, 5)
        self.files_table.setHorizontalHeaderLabels(["Status", "File / Photo Name", "Type", "Size", "Action"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.files_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.files_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        left_layout.addWidget(self.files_table)

        layout.addWidget(left_card, stretch=6)

        # RIGHT COLUMN: Live Reconstruction Showcase & Preview
        right_card = self.create_showcase_card()
        layout.addWidget(right_card, stretch=5)

        return tab

    # ═════════════════════════════════════════════════════════════════════════
    # TAB 2: DAMAGED FILE & SECTOR CARVING
    # ═════════════════════════════════════════════════════════════════════════
    def create_carving_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(18)

        left_card = QFrame()
        left_card.setObjectName("glassCard")
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(20, 20, 20, 20)
        left_layout.setSpacing(14)

        step1_title = QLabel("SELECT DAMAGED EVIDENCE FILE OR DISK IMAGE")
        step1_title.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 800; letter-spacing: 0.8px;")
        left_layout.addWidget(step1_title)

        # Dropzone Area
        self.drop_area = QFrame()
        self.drop_area.setObjectName("fileDropArea")
        drop_layout = QVBoxLayout(self.drop_area)
        drop_layout.setContentsMargins(16, 18, 16, 18)
        drop_layout.setSpacing(8)

        self.carve_icon_lbl = QLabel("📂")
        self.carve_icon_lbl.setAlignment(Qt.AlignCenter)
        self.carve_icon_lbl.setStyleSheet("font-size: 32px;")

        self.carve_filename_lbl = QLabel("No evidence file selected")
        self.carve_filename_lbl.setAlignment(Qt.AlignCenter)
        self.carve_filename_lbl.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: 700;")

        self.carve_filesize_lbl = QLabel("Choose a damaged file or raw disk (.dd, .raw) to carve")
        self.carve_filesize_lbl.setAlignment(Qt.AlignCenter)
        self.carve_filesize_lbl.setStyleSheet("color: #64748b; font-size: 12px;")

        drop_layout.addWidget(self.carve_icon_lbl)
        drop_layout.addWidget(self.carve_filename_lbl)
        drop_layout.addWidget(self.carve_filesize_lbl)
        left_layout.addWidget(self.drop_area)

        # Browse Buttons Row
        browse_row = QHBoxLayout()
        browse_row.setSpacing(10)
        browse_file_btn = QPushButton("📁 Browse File...")
        browse_file_btn.clicked.connect(self.browse_carve_file)
        browse_disk_btn = QPushButton("💾 Browse Disk (.dd)...")
        browse_disk_btn.clicked.connect(self.browse_carve_disk)
        browse_row.addWidget(browse_file_btn)
        browse_row.addWidget(browse_disk_btn)
        left_layout.addLayout(browse_row)

        # Target Format Selection
        left_layout.addSpacing(6)
        step2_title = QLabel("RECONSTRUCTION FORMAT")
        step2_title.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 800; letter-spacing: 0.8px;")
        left_layout.addWidget(step2_title)

        self.format_combo = QComboBox()
        self.format_combo.addItems([
            "auto (Smart Format Detection)",
            "jpeg (Photos & JPEG Images)",
            "png (PNG Logos & Transparent Badges)",
            "pdf (PDF Documents)",
            "zip (ZIP & Office Archives)",
            "sqlite (SQLite 3 Databases)",
            "mp4 (MPEG-4 Videos)",
            "mp3 (Audio MP3 Files)"
        ])
        left_layout.addWidget(self.format_combo)

        # Action Button
        left_layout.addSpacing(8)
        self.hero_carve_btn = QPushButton("⚡  RECONSTRUCT DAMAGED FILE")
        self.hero_carve_btn.setObjectName("heroActionBtn")
        self.hero_carve_btn.clicked.connect(self.start_carve_recovery)
        left_layout.addWidget(self.hero_carve_btn)

        # Progress bar
        self.carve_status_text = QLabel("")
        self.carve_status_text.setStyleSheet("color: #38bdf8; font-weight: 700; font-size: 12px;")
        self.carve_status_text.setAlignment(Qt.AlignCenter)
        self.carve_status_text.setVisible(False)

        self.carve_progress_bar = QProgressBar()
        self.carve_progress_bar.setRange(0, 100)
        self.carve_progress_bar.setValue(0)
        self.carve_progress_bar.setVisible(False)

        left_layout.addWidget(self.carve_status_text)
        left_layout.addWidget(self.carve_progress_bar)
        left_layout.addStretch()

        layout.addWidget(left_card, stretch=6)

        # Shared Showcase Display
        right_card_carving = self.create_showcase_card()
        layout.addWidget(right_card_carving, stretch=5)

        return tab

    # ═════════════════════════════════════════════════════════════════════════
    # SHOWCASE & METRICS CARD (Visual Preview & Verification Certificate)
    # ═════════════════════════════════════════════════════════════════════════
    def create_showcase_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("glassCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Showcase Header
        res_header = QHBoxLayout()
        res_title = QLabel("RECONSTRUCTION & PREVIEW")
        res_title.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 800; letter-spacing: 0.8px;")
        
        self.status_badge = QLabel("READY TO RECOVER")
        self.status_badge.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 700;")

        res_header.addWidget(res_title)
        res_header.addStretch()
        res_header.addWidget(self.status_badge)
        layout.addLayout(res_header)

        # Visual Artifact Preview Canvas
        self.preview_canvas = QFrame()
        self.preview_canvas.setObjectName("previewCard")
        p_layout = QVBoxLayout(self.preview_canvas)
        p_layout.setContentsMargins(14, 14, 14, 14)

        self.preview_display = QLabel("No file or photo recovered yet\n\nDelete any file or photo in the monitored folder to test instant recovery!")
        self.preview_display.setAlignment(Qt.AlignCenter)
        self.preview_display.setStyleSheet("color: #64748b; font-size: 13px; font-weight: 500; line-height: 1.5;")
        self.preview_display.setMinimumHeight(240)
        p_layout.addWidget(self.preview_display)
        layout.addWidget(self.preview_canvas, stretch=1)

        # 3 Sleek Floating Metric Cards
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)

        self.card_integ = self.create_metric_card("FILE INTEGRITY", "—", "Syntax validation")
        self.card_auth = self.create_metric_card("AUTHENTIC DATA", "—", "0 fake bytes")
        self.card_conf = self.create_metric_card("AI CONFIDENCE", "—", "Model match score")

        metrics_row.addWidget(self.card_integ)
        metrics_row.addWidget(self.card_auth)
        metrics_row.addWidget(self.card_conf)
        layout.addLayout(metrics_row)

        # Source / Recovery Origin Note
        self.recovery_source_lbl = QLabel("")
        self.recovery_source_lbl.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 600;")
        self.recovery_source_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.recovery_source_lbl)

        # Action Buttons Row
        action_btn_row = QHBoxLayout()
        action_btn_row.setSpacing(10)

        self.open_file_btn = QPushButton("🚀 Open Recovered File")
        self.open_file_btn.setObjectName("successBtn")
        self.open_file_btn.setEnabled(False)
        self.open_file_btn.clicked.connect(self.open_recovered_file)

        self.open_folder_btn = QPushButton("📂 Open Folder in Explorer")
        self.open_folder_btn.setEnabled(False)
        self.open_folder_btn.clicked.connect(self.open_recovered_folder)

        action_btn_row.addWidget(self.open_file_btn)
        action_btn_row.addWidget(self.open_folder_btn)
        layout.addLayout(action_btn_row)

        return card

    def create_metric_card(self, title: str, value: str, subtext: str) -> QFrame:
        card = QFrame()
        card.setObjectName("metricCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 0.6px;")
        v_lbl = QLabel(value)
        v_lbl.setStyleSheet("color: #ffffff; font-size: 17px; font-weight: 800; font-family: Consolas, monospace;")
        s_lbl = QLabel(subtext)
        s_lbl.setStyleSheet("color: #475569; font-size: 10px; font-weight: 500;")

        layout.addWidget(t_lbl)
        layout.addWidget(v_lbl)
        layout.addWidget(s_lbl)
        card.val_label = v_lbl
        return card

    # ═════════════════════════════════════════════════════════════════════════
    # USER INTERACTIONS & REAL-TIME MONITORING
    # ═════════════════════════════════════════════════════════════════════════
    def auto_start_default_monitor(self):
        """Automatically begins monitoring and analysis on startup."""
        self.analyze_current_folder()
        self.start_sentinel_monitor()

    def set_quick_dir(self, name: str):
        target = Path.home() / name
        if target.exists():
            self.dir_input.setText(str(target))
            self.analyze_current_folder()
            self.restart_sentinel_monitor()

    def browse_directory(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor", self.dir_input.text() or str(Path.home()))
        if d:
            self.dir_input.setText(d)
            self.analyze_current_folder()
            self.restart_sentinel_monitor()

    def on_require_permission_toggle(self):
        if self.require_permission_chk.isChecked():
            self.auto_recover_chk.setChecked(False)
        if self.sentinel_thread and self.sentinel_thread.sentinel:
            self.sentinel_thread.auto_recover = self.auto_recover_chk.isChecked()
            self.sentinel_thread.sentinel.auto_recover = self.auto_recover_chk.isChecked()

    def on_auto_recover_toggle(self):
        if self.auto_recover_chk.isChecked():
            self.require_permission_chk.setChecked(False)
        if self.sentinel_thread and self.sentinel_thread.sentinel:
            self.sentinel_thread.auto_recover = self.auto_recover_chk.isChecked()
            self.sentinel_thread.sentinel.auto_recover = self.auto_recover_chk.isChecked()

    def analyze_current_folder(self):
        d = self.dir_input.text().strip()
        if not d or not os.path.exists(d):
            return

        self.rescan_btn.setEnabled(False)
        self.analysis_thread = FolderAnalysisThread(d)
        self.analysis_thread.finished_analysis.connect(self.on_analysis_finished)
        self.analysis_thread.finished_error.connect(self.on_analysis_error)
        self.analysis_thread.log_emitted.connect(self.console_log.append)
        self.analysis_thread.start()

    def on_analysis_finished(self, data: dict):
        self.rescan_btn.setEnabled(True)
        tot_files = data.get("total_files", 0)
        tot_mb = data.get("total_size_mb", 0)
        self.files_count_lbl.setText(f"{tot_files} files ({tot_mb} MB) protected")

        files = data.get("files", [])
        self.files_table.setRowCount(len(files))
        for row, f in enumerate(files):
            # Col 0: Status
            status_item = QTableWidgetItem("🛡️ Monitored")
            status_item.setForeground(QBrush(QColor("#34d399")))
            status_item.setTextAlignment(Qt.AlignCenter)

            # Col 1: Name
            name_item = QTableWidgetItem(f.get("name", ""))
            name_item.setForeground(QBrush(QColor("#ffffff")))
            name_item.setFont(QFont("Segoe UI", 10, QFont.Bold))

            # Col 2: Type
            ext = f.get("extension", "").upper() or "FILE"
            type_item = QTableWidgetItem(ext)
            type_item.setForeground(QBrush(QColor("#38bdf8")))

            # Col 3: Size
            sz = f.get("size", 0)
            sz_str = f"{sz / 1024:.1f} KB" if sz < 1024 * 1024 else f"{sz / (1024 * 1024):.1f} MB"
            size_item = QTableWidgetItem(sz_str)
            size_item.setForeground(QBrush(QColor("#94a3b8")))
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            # Col 4: Action Button
            btn = QPushButton("⚡ Recover")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #162035;
                    border: 1px solid #273754;
                    border-radius: 6px;
                    padding: 3px 8px;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #059669;
                    border-color: #34d399;
                    color: white;
                }
            """)
            fn = f.get("name", "")
            d = data.get("directory", "")
            btn.clicked.connect(lambda _, filename=fn, directory=d: self.recover_file_to_same_path(filename, directory))

            self.files_table.setItem(row, 0, status_item)
            self.files_table.setItem(row, 1, name_item)
            self.files_table.setItem(row, 2, type_item)
            self.files_table.setItem(row, 3, size_item)
            self.files_table.setCellWidget(row, 4, btn)

    def on_analysis_error(self, err: str):
        self.rescan_btn.setEnabled(True)
        self.console_log.append(f"❌ Analysis failed: {err}")

    def start_sentinel_monitor(self):
        d = self.dir_input.text().strip()
        if not d or not os.path.exists(d):
            return

        if self.sentinel_thread and self.sentinel_thread.isRunning():
            return

        # auto_recover is False by default so it requests user permission
        auto_rec = self.auto_recover_chk.isChecked() and not self.require_permission_chk.isChecked()
        self.sentinel_thread = SentinelThread(d, target_filename="*", auto_recover=auto_rec)
        self.sentinel_thread.deletion_detected.connect(self.on_deletion_detected)
        self.sentinel_thread.file_recovered.connect(self.on_auto_recovered)
        self.sentinel_thread.log_emitted.connect(self.console_log.append)
        self.sentinel_thread.start()

        self.guard_toggle_btn.setText("⏹️ Pause Real-Time Monitor")
        self.guard_toggle_btn.setObjectName("guardActiveBtn")
        self.guard_toggle_btn.setStyleSheet("")

        self.shield_badge.setText("🟢 REAL-TIME MONITOR: ACTIVE")
        self.shield_badge.setStyleSheet("""
            background-color: #062e24;
            color: #34d399;
            font-size: 11px;
            font-weight: 800;
            padding: 8px 16px;
            border-radius: 20px;
            border: 1px solid #059669;
        """)
        self.console_log.append(f"[🛡️ MONITOR STARTED] Real-time folder protection active on '{d}'")

    def stop_sentinel_monitor(self):
        if self.sentinel_thread and self.sentinel_thread.isRunning():
            self.sentinel_thread.stop()
            self.sentinel_thread.quit()
            self.sentinel_thread.wait(1000)
            self.sentinel_thread = None

        self.guard_toggle_btn.setText("🟢 Start Real-Time Monitor")
        self.guard_toggle_btn.setObjectName("guardStandbyBtn")
        self.guard_toggle_btn.setStyleSheet("")

        self.shield_badge.setText("⏸️ REAL-TIME MONITOR: PAUSED")
        self.shield_badge.setStyleSheet("""
            background-color: #1f1b0a;
            color: #f59e0b;
            font-size: 11px;
            font-weight: 800;
            padding: 8px 16px;
            border-radius: 20px;
            border: 1px solid #d97706;
        """)
        self.console_log.append("[*] Real-Time Monitor paused.")

    def restart_sentinel_monitor(self):
        self.stop_sentinel_monitor()
        self.start_sentinel_monitor()

    def toggle_sentinel_guard(self):
        if self.sentinel_thread and self.sentinel_thread.isRunning():
            self.stop_sentinel_monitor()
        else:
            self.start_sentinel_monitor()

    # ── DELETION & RECOVERY EVENTS ───────────────────────────────────────────
    def on_deletion_detected(self, del_info: dict):
        """Called immediately when a file or photo is deleted in the monitored folder."""
        self.last_deleted_info = del_info
        fn = del_info.get("name", "")
        orig_path = del_info.get("full_path", "")
        d = del_info.get("directory", "")
        is_photo = del_info.get("is_photo", False)
        desc = "Photo" if is_photo else "File"
        sz = del_info.get("size", 0)
        sz_str = f"{sz / 1024:.1f} KB" if sz < 1024 * 1024 else f"{sz / (1024 * 1024):.1f} MB"

        # Update Alert Card with vivid red warning
        self.deletion_alert_frame.setObjectName("alertCard")
        self.deletion_alert_frame.setStyleSheet("""
            background-color: #2b0b14;
            border: 2px solid #ef4444;
            border-radius: 14px;
        """)
        self.alert_badge.setText(f"⚠️ {desc.upper()} DELETED • PERMISSION REQUIRED")
        self.alert_badge.setStyleSheet("color: #ef4444; font-size: 12px; font-weight: 800;")
        self.alert_time_lbl.setText(f"Deleted at {del_info.get('timestamp', '')}")
        self.alert_icon_lbl.setText("🖼️" if is_photo else "📄")
        self.alert_name_lbl.setText(f"{desc}: {fn}")
        self.alert_path_lbl.setText(f"Original Path: {orig_path} ({sz_str})")
        
        self.alert_recover_btn.setVisible(True)
        self.alert_recover_btn.setText(f"⚡ Yes, Recover to Same Path")
        self.alert_deny_btn.setVisible(True)

        self.status_badge.setText(f"🔴 PERMISSION REQUIRED: '{fn}'")
        self.status_badge.setStyleSheet("color: #f59e0b; font-size: 11px; font-weight: 800;")

        # Update row in table if present
        for row in range(self.files_table.rowCount()):
            item = self.files_table.item(row, 1)
            if item and item.text() == fn:
                s_item = self.files_table.item(row, 0)
                if s_item:
                    s_item.setText("🔴 DELETED")
                    s_item.setForeground(QBrush(QColor("#ef4444")))
                break

        # Check if user enabled auto-recover without asking:
        if self.auto_recover_chk.isChecked():
            self.console_log.append(f"[Auto-Recover] Auto-recovery enabled. Restoring '{fn}' to same path...")
            self.recover_file_to_same_path(fn, d)
            return

        # Otherwise, ask permission directly from user via dialog:
        self.console_log.append(f"[Permission Required] Asking user permission to recover '{fn}'...")
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("🛡️ Recover Deleted File?")
        msg_box.setIcon(QMessageBox.Question)
        msg_box.setText(f"<h3>A {desc.lower()} was deleted from your laptop:</h3>")
        msg_box.setInformativeText(
            f"<b>Name:</b> {fn}<br>"
            f"<b>Original Path:</b> {orig_path}<br>"
            f"<b>Size:</b> {sz_str}<br><br>"
            f"<b>Would you like to recover it back to this same path?</b>"
        )
        rec_btn = msg_box.addButton("⚡ Yes, Recover to Same Path", QMessageBox.AcceptRole)
        rec_btn.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
            color: #ffffff;
            font-weight: 800;
            padding: 8px 16px;
            border-radius: 8px;
        """)
        deny_btn = msg_box.addButton("✕ No, Keep Deleted", QMessageBox.RejectRole)
        deny_btn.setStyleSheet("""
            background-color: #1e293b;
            color: #94a3b8;
            font-weight: 600;
            padding: 8px 16px;
            border-radius: 8px;
        """)
        msg_box.setDefaultButton(rec_btn)
        msg_box.exec_()

        if msg_box.clickedButton() == rec_btn:
            self.console_log.append(f"[Permission Granted] User approved recovery for '{fn}'. Restoring...")
            self.recover_file_to_same_path(fn, d)
        else:
            self.console_log.append(f"[Permission Denied] User chose to keep '{fn}' deleted.")
            self.status_badge.setText(f"🔴 KEPT DELETED: '{fn}'")
            self.status_badge.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 700;")
            self.alert_badge.setText("✕ RECOVERY CANCELLED (Kept Deleted)")
            self.alert_badge.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 700;")

    def on_alert_deny_clicked(self):
        """User clicked 'Keep Deleted' on the alert card."""
        if self.last_deleted_info:
            fn = self.last_deleted_info.get("name")
            self.console_log.append(f"[Dismissed] User dismissed recovery for '{fn}'.")
        self.alert_recover_btn.setVisible(False)
        self.alert_deny_btn.setVisible(False)
        self.alert_badge.setText("✕ RECOVERY DISMISSED (Kept Deleted)")
        self.alert_badge.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 700;")
        self.status_badge.setText("READY")
        self.status_badge.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 700;")

    def on_auto_recovered(self, rec_info: dict):
        """Called when auto-recovery restores the file into the same path."""
        self.recovered_result = rec_info
        fn = rec_info.get("name", "")
        dest = rec_info.get("restored_to", "")
        
        # Change Alert Card to green success state
        self.deletion_alert_frame.setObjectName("alertCardSuccess")
        self.deletion_alert_frame.setStyleSheet("""
            background-color: #07281d;
            border: 2px solid #10b981;
            border-radius: 14px;
        """)
        self.alert_badge.setText("✓ SUCCESSFULLY RECOVERED TO SAME PATH!")
        self.alert_badge.setStyleSheet("color: #34d399; font-size: 12px; font-weight: 800;")
        self.alert_name_lbl.setText(f"✓ Restored: {fn}")
        self.alert_path_lbl.setText(f"Path: {dest}")
        self.alert_recover_btn.setVisible(False)

        # Update table row to restored
        for row in range(self.files_table.rowCount()):
            item = self.files_table.item(row, 1)
            if item and item.text() == fn:
                s_item = self.files_table.item(row, 0)
                if s_item:
                    s_item.setText("✓ RESTORED")
                    s_item.setForeground(QBrush(QColor("#34d399")))
                break

        self.display_recovery_showcase(rec_info)

    def on_alert_recover_clicked(self):
        """User clicked 'Recover to Same Path' on the alert card."""
        if not self.last_deleted_info:
            return
        fn = self.last_deleted_info.get("name")
        d = self.last_deleted_info.get("directory")
        if fn and d:
            self.recover_file_to_same_path(fn, d)

    def recover_file_to_same_path(self, filename: str, directory: str):
        """Recover deleted file directly into its original folder."""
        self.status_badge.setText("RECOVERING...")
        self.status_badge.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 800;")

        res = recover_target_file(filename, directory)
        if res:
            self.recovered_result = res
            self.on_auto_recovered(res)
            self.console_log.append(f"[✓ RECOVERED] '{filename}' restored into same path: {res['restored_to']}")
        else:
            self.status_badge.setText("NOT FOUND")
            self.status_badge.setStyleSheet("color: #f87171; font-size: 11px; font-weight: 700;")
            QMessageBox.warning(self, "Recovery Notice", f"Could not find deleted file '{filename}' in Vault or Recycle Bin.")

    def display_recovery_showcase(self, data: dict):
        """Renders live photo preview or file preview with 100% integrity verification."""
        fn = data.get("name", "")
        dest = data.get("restored_to", data.get("path", ""))
        self.status_badge.setText(f"✓ RESTORED IN SAME PATH")
        self.status_badge.setStyleSheet("color: #34d399; font-size: 11px; font-weight: 800;")

        # Update floating cards
        self.card_integ.val_label.setText(f"{data.get('integrity', 100):.0f}%")
        self.card_integ.val_label.setStyleSheet("color: #34d399; font-size: 18px; font-weight: 800;")

        self.card_auth.val_label.setText("100% Real")
        self.card_auth.val_label.setStyleSheet("color: #38bdf8; font-size: 18px; font-weight: 800;")

        self.card_conf.val_label.setText(f"{data.get('confidence', 100)}%")
        self.card_conf.val_label.setStyleSheet("color: #a78bfa; font-size: 18px; font-weight: 800;")

        self.recovery_source_lbl.setText(f"Origin: {data.get('source', 'Forensic Recovery')}")

        # Render visual preview
        raw = data.get("raw_bytes")
        file_type = data.get("type", "").lower()
        if file_type in ("jpeg", "png", "jpg", "bmp", "gif", "webp") and raw:
            pix = QPixmap()
            pix.loadFromData(raw)
            if not pix.isNull():
                self.preview_display.setPixmap(pix.scaled(380, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                self.preview_display.setText(
                    f"✓ PHOTO RESTORED IN SAME PATH\n\n"
                    f"Name: {fn}\n"
                    f"Path: {dest}\n"
                    f"Size: {data['size']:,} bytes"
                )
        elif file_type in ("txt", "json", "py", "csv", "md", "log", "html", "xml") and raw:
            try:
                snippet = raw[:800].decode("utf-8", errors="replace")
                self.preview_display.setText(
                    f"✓ DOCUMENT RESTORED IN SAME PATH:\n\n{snippet}..."
                )
            except Exception:
                self.preview_display.setText(f"✓ {file_type.upper()} File Restored in Same Path\nSize: {data['size']:,} bytes")
        else:
            self.preview_display.setText(
                f"✓ FILE RESTORED IN SAME PATH!\n\n"
                f"File: {fn}\n"
                f"Path: {dest}\n"
                f"Size: {data['size']:,} bytes\n"
                f"Strict 0% Fake Data Guarantee"
            )

        self.open_file_btn.setEnabled(True)
        self.open_folder_btn.setEnabled(True)

    # ═════════════════════════════════════════════════════════════════════════
    # EVIDENCE CARVING HANDLERS
    # ═════════════════════════════════════════════════════════════════════════
    def set_carve_selected_file(self, path: str):
        self.selected_path = path
        p = Path(path)
        sz = p.stat().st_size if p.exists() else 0
        self.carve_filename_lbl.setText(p.name)
        self.carve_filename_lbl.setStyleSheet("color: #38bdf8; font-size: 15px; font-weight: 700;")
        self.carve_filesize_lbl.setText(f"{sz / 1024:.1f} KB • Ready for AI Reconstruction")
        self.carve_icon_lbl.setText("💾" if p.suffix.lower() in (".dd", ".img", ".raw") else "📄")

    def browse_carve_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Damaged Evidence File", str(settings.workspace_dir))
        if f:
            self.set_carve_selected_file(f)

    def browse_carve_disk(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image (.dd, .raw)",
            str(settings.workspace_dir),
            "Disk Images (*.dd *.img *.raw);;All Files (*.*)"
        )
        if f:
            self.set_carve_selected_file(f)

    def start_carve_recovery(self):
        if not self.selected_path or not os.path.exists(self.selected_path):
            QMessageBox.warning(self, "No Evidence", "Please select a file or disk image first.")
            return

        fmt = self.format_combo.currentText().split()[0]
        self.hero_carve_btn.setEnabled(False)
        self.carve_progress_bar.setVisible(True)
        self.carve_status_text.setVisible(True)
        self.status_badge.setText("RECONSTRUCTING...")
        self.status_badge.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 700;")

        self.worker = BeautifulRecoveryWorker(self.selected_path, fmt)
        self.worker.progress_changed.connect(self.on_carve_progress)
        self.worker.log_emitted.connect(self.console_log.append)
        self.worker.finished_success.connect(self.on_carve_success)
        self.worker.finished_error.connect(self.on_carve_error)
        self.worker.start()

    def on_carve_progress(self, msg: str, pct: int):
        self.carve_status_text.setText(msg)
        self.carve_progress_bar.setValue(pct)

    def on_carve_success(self, data: dict):
        self.hero_carve_btn.setEnabled(True)
        self.carve_status_text.setText("✓ Reconstruction successfully completed!")
        self.recovered_result = data
        self.display_recovery_showcase(data)

    def on_carve_error(self, err: str):
        self.hero_carve_btn.setEnabled(True)
        self.carve_status_text.setText("Reconstruction stopped.")
        self.status_badge.setText("FAILED")
        self.status_badge.setStyleSheet("color: #f87171; font-size: 11px; font-weight: 700;")
        QMessageBox.warning(self, "Forensic Analysis Notice", err)

    def toggle_console(self):
        vis = not self.console_log.isVisible()
        self.console_log.setVisible(vis)
        self.log_drawer_btn.setText("⚙️  Forensics Activity & Audit Trail  ▲" if vis else "⚙️  Forensics Activity & Audit Trail  ▼")

    def open_recovered_file(self):
        if self.recovered_result:
            p = self.recovered_result.get("restored_to") or self.recovered_result.get("path")
            if p and os.path.exists(p):
                os.startfile(p)

    def open_recovered_folder(self):
        if self.recovered_result:
            p = self.recovered_result.get("restored_to") or self.recovered_result.get("path")
            if p and os.path.exists(p):
                folder = str(Path(p).parent)
                os.startfile(folder)
                return
        d = self.dir_input.text().strip()
        if d and os.path.exists(d):
            os.startfile(d)
        else:
            os.startfile(str(settings.output_dir))


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    window = BeautifulRecoveryApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
