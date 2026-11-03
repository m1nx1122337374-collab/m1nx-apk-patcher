from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QMainWindow, QMessageBox, QProgressBar, QPushButton, QSplitter,
    QTextEdit, QVBoxLayout, QWidget
)

from core.analyzer import APKAnalyzer
from core.restoration import RestorationService


class Worker(QThread):
    finished_data = Signal(object)
    failed = Signal(str)
    progress = Signal(int)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args

    def run(self):
        try:
            self.progress.emit(20)
            data = self.fn(*self.args)
            self.progress.emit(100)
            self.finished_data.emit(data)
        except Exception as exc:
            self.failed.emit(str(exc))


class DropZone(QFrame):
    fileDropped = Signal(str)
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setObjectName("dropZone")
        label = QLabel("DROP APK HERE\n\n—or click APK SELECT below")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setObjectName("dropLabel")
        layout = QVBoxLayout(self)
        layout.addWidget(label)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()
    def dropEvent(self, event):
        for url in event.mimeData().urls():
            if url.toLocalFile().lower().endswith(".apk"):
                self.fileDropped.emit(url.toLocalFile()); break


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("M1NX VIP APK ANALYZER")
        self.resize(1180, 760)
        self.analyzer, self.restorer = APKAnalyzer(), RestorationService()
        self.selected: Path | None = None
        self.original: Path | None = None
        self.restored: Path | None = None
        self.worker: Worker | None = None
        self._build_ui()

    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root)
        main = QVBoxLayout(root); main.setContentsMargins(28, 24, 28, 24); main.setSpacing(18)
        header = QHBoxLayout()
        title = QLabel("M1NX VIP\nAPK ANALYZER")
        title.setObjectName("title")
        subtitle = QLabel("AUTHORIZED INSPECTION  /  EVIDENCE-BASED RESTORATION")
        subtitle.setObjectName("subtitle")
        header.addWidget(title); header.addStretch(); header.addWidget(subtitle)
        main.addLayout(header)
        self.drop = DropZone(); self.drop.fileDropped.connect(self.set_apk); main.addWidget(self.drop)
        self.file_label = QLabel("No APK selected"); self.file_label.setObjectName("fileLabel"); main.addWidget(self.file_label)
        controls = QHBoxLayout()
        for text, slot, obj in [
            ("APK SELECT", self.select_apk, "primary"), ("START ANALYSIS", self.analyze, "primary"),
            ("COMPARE APK", self.compare, "secondary"), ("RESTORE APK", self.restore, "warning"),
            ("EXPORT APK", self.export_apk, "success")]:
            b = QPushButton(text); b.setObjectName(obj); b.clicked.connect(slot); controls.addWidget(b)
        main.addLayout(controls)
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setValue(0); main.addWidget(self.progress)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.summary = QTextEdit(); self.summary.setReadOnly(True); self.summary.setPlaceholderText("Analysis summary will appear here")
        self.report = QTextEdit(); self.report.setReadOnly(True); self.report.setPlaceholderText("Detailed evidence report will appear here")
        split.addWidget(self.summary); split.addWidget(self.report); split.setSizes([380, 700]); main.addWidget(split, 1)
        note = QLabel("Safety: this tool does not bypass authentication, licensing, anti-cheat, DRM, signatures, or access controls. Restoration requires a trusted original or your own source/backup.")
        note.setObjectName("note"); note.setWordWrap(True); main.addWidget(note)
        self.setStyleSheet(STYLE)

    def select_apk(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select APK", "", "Android Package (*.apk)")
        if path: self.set_apk(path)

    def set_apk(self, path: str):
        self.selected = Path(path)
        self.file_label.setText(f"Selected: {self.selected.name}  •  {self.selected.stat().st_size / 1024 / 1024:.2f} MB")
        self.summary.setPlainText("APK ready. Start analysis to inspect archive structure and protection indicators.")

    def analyze(self):
        if not self.selected: return self.warn("Select an APK first")
        self.run_worker(self.analyzer.inspect, self.selected, self.show_analysis)

    def show_analysis(self, data):
        self.summary.setPlainText(
            f"FILE\n{data['file']}\n\nSIZE\n{data['size']:,} bytes\n\nSHA-256\n{data['sha256']}\n\nPACKAGE\n{data['package']}\n\nVERSION\n{data['version']}\n\nDEX FILES\n{data.get('dex_count', 0)}\n\nNATIVE LIBS\n{data.get('native_libs', 0)}\n\nCERTIFICATES\n{len(data.get('certificate_files', []))}"
        )
        self.report.setPlainText(json.dumps({"signals": data["signals"], "warnings": data["warnings"]}, indent=2, ensure_ascii=False))

    def compare(self):
        if not self.selected: return self.warn("Select the modified APK first")
        path, _ = QFileDialog.getOpenFileName(self, "Select trusted original APK", "", "Android Package (*.apk)")
        if not path: return
        self.original = Path(path)
        self.run_worker(self.analyzer.compare, self.original, self.selected, self.show_compare)

    def show_compare(self, data):
        self.report.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))
        self.summary.setPlainText(f"ADDED  {len(data['added'])}\nREMOVED  {len(data['removed'])}\nCHANGED  {len(data['changed'])}\nUNCHANGED  {len(data['same'])}")

    def restore(self):
        if not self.selected: return self.warn("Select an APK first")
        msg = QMessageBox(self); msg.setWindowTitle("Authorized restoration source")
        msg.setText("Choose a trusted original APK or a source/backup directory. No automatic protection removal is performed.")
        original = msg.addButton("Trusted original APK", QMessageBox.ButtonRole.AcceptRole)
        source = msg.addButton("Source / backup folder", QMessageBox.ButtonRole.ActionRole)
        msg.addButton(QMessageBox.StandardButton.Cancel); msg.exec()
        if msg.clickedButton() == original:
            path, _ = QFileDialog.getOpenFileName(self, "Select trusted original APK", "", "Android Package (*.apk)")
            if path: self.original = Path(path); self.run_worker(self._restore_original, self.original, self.show_restored)
        elif msg.clickedButton() == source:
            path = QFileDialog.getExistingDirectory(self, "Select source or backup folder")
            if path: self.run_worker(self._restore_source, Path(path), self.show_restored)

    def _restore_original(self, source):
        out = Path.cwd() / "exports" / "restored_from_trusted_original.apk"
        return {"path": str(self.restorer.restore_from_apk(source, out)), "verification": self.restorer.verify(out)}

    def _restore_source(self, source):
        out = Path.cwd() / "exports" / "restored_from_source.apk"
        return {"path": str(self.restorer.rebuild_from_source(source, out)), "verification": self.restorer.verify(out)}

    def show_restored(self, data):
        self.restored = Path(data["path"]); self.report.setPlainText(json.dumps(data, indent=2, ensure_ascii=False)); self.summary.setPlainText("RESTORATION READY\nUse EXPORT APK to choose a destination.")

    def export_apk(self):
        if not self.restored or not self.restored.exists(): return self.warn("Restore an APK first")
        path, _ = QFileDialog.getSaveFileName(self, "Export restored APK", "M1NX_restored.apk", "Android Package (*.apk)")
        if path: shutil.copy2(self.restored, path); self.statusBar().showMessage(f"Exported: {path}", 5000)

    def run_worker(self, fn, *args):
        callback = args[-1]; args = args[:-1]
        self.progress.setValue(5); self.worker = Worker(fn, *args); self.worker.progress.connect(self.progress.setValue); self.worker.finished_data.connect(callback); self.worker.failed.connect(lambda e: self.warn(e)); self.worker.start()

    def warn(self, text): QMessageBox.warning(self, "M1NX VIP", text)


STYLE = """
QMainWindow, QWidget { background: #0b1020; color: #e7edf8; font-family: Inter, Segoe UI, sans-serif; }
#title { color: #f6f8ff; font-size: 28px; font-weight: 800; letter-spacing: 1px; }
#subtitle { color: #7181a6; font-size: 11px; letter-spacing: 2px; }
#dropZone { min-height: 145px; border: 1px dashed #3d5a91; border-radius: 18px; background: #101a31; }
#dropLabel { color: #7f9ee8; font-size: 16px; font-weight: 600; }
#fileLabel { color: #aebbd8; padding: 4px 8px; }
QPushButton { min-height: 42px; padding: 0 18px; border-radius: 10px; font-weight: 800; letter-spacing: .5px; }
#primary { background: #5d7cf2; color: white; } #primary:hover { background: #7892ff; }
#secondary { background: #192846; color: #b9caff; border: 1px solid #304875; }
#warning { background: #a96f35; color: white; } #success { background: #267b67; color: white; }
QTextEdit { background: #0f172b; border: 1px solid #223456; border-radius: 12px; padding: 14px; color: #c9d5ec; font-family: JetBrains Mono, monospace; }
QProgressBar { background: #101a31; border: none; border-radius: 5px; height: 8px; } QProgressBar::chunk { background: #5d7cf2; border-radius: 5px; }
#note { color: #7f8cab; font-size: 11px; padding: 8px; }
"""

if __name__ == "__main__":
    app = QApplication(sys.argv); app.setApplicationName("M1NX VIP APK ANALYZER"); window = MainWindow(); window.show(); sys.exit(app.exec())
