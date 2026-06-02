from datetime import datetime, timezone
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QSplitter, QPlainTextEdit,
)


def _placeholder_panel(text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class ScanViewScreen(QWidget):
    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._target_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._pipeline_panel: QFrame | None = None
        self._attack_graph_panel: QFrame | None = None
        self._severity_panel: QFrame | None = None
        self._finding_cards_panel: QFrame | None = None
        self._terminal_panel: QPlainTextEdit | None = None
        self._worker = None
        self._scan_id: int | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top_bar = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.setToolTip("Enter a target and click to scan" if self._db else "DB not initialised")
        self._start_btn.clicked.connect(self._on_start_cancel)
        top_bar.addWidget(self._target_input, stretch=1)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(self._status_label)

        self._pipeline_panel = _placeholder_panel("Pipeline Tracker\nPhase 3")
        self._attack_graph_panel = _placeholder_panel("Attack Surface Graph\nPhase 3")
        self._severity_panel = _placeholder_panel("Severity\nRings\nPhase 3")
        self._finding_cards_panel = _placeholder_panel("Finding Cards Stream\nPhase 3")

        self._terminal_panel = QPlainTextEdit()
        self._terminal_panel.setReadOnly(True)
        self._terminal_panel.setObjectName("panel")
        self._terminal_panel.setStyleSheet(
            "font-family: monospace; font-size: 11px; color: #00ff88; background-color: #0a0e1a;"
        )

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._pipeline_panel)
        top_splitter.addWidget(self._attack_graph_panel)
        top_splitter.setSizes([250, 750])

        mid_splitter = QSplitter(Qt.Orientation.Horizontal)
        mid_splitter.addWidget(self._severity_panel)
        mid_splitter.addWidget(self._finding_cards_panel)
        mid_splitter.setSizes([250, 750])

        top_mid = QWidget()
        top_mid_layout = QVBoxLayout(top_mid)
        top_mid_layout.setContentsMargins(0, 0, 0, 0)
        top_mid_layout.setSpacing(8)
        top_mid_layout.addWidget(top_splitter, stretch=1)
        top_mid_layout.addWidget(mid_splitter, stretch=1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_mid)
        main_splitter.addWidget(self._terminal_panel)
        main_splitter.setSizes([800, 200])

        layout.addWidget(main_splitter, stretch=1)

    def _on_start_cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            return

        target = self._target_input.text().strip()
        if not target:
            self._status_label.setText("Enter a target first.")
            return

        from models import Scan
        from workers.scan_worker import ScanWorker

        scan = Scan(
            id=None,
            client_id=None,
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)
        self._worker.tool_started.connect(lambda name: self._status_label.setText(f"{name} — running…"))
        self._worker.tool_finished.connect(lambda name, n: self._status_label.setText(f"{name} — {n} items"))
        self._worker.tool_failed.connect(lambda name, msg: self._log(f"[FAILED] {name}: {msg}"))
        self._worker.log_line.connect(self._log)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_failed.connect(self._on_scan_failed)

        self._start_btn.setText("■  Cancel")
        self._terminal_panel.clear()
        self._worker.start()

    def _log(self, line: str):
        self._terminal_panel.appendPlainText(line)

    def _on_scan_complete(self, hosts: int, findings: int):
        self._status_label.setText(f"Complete — {hosts} hosts, {findings} findings")
        self._start_btn.setText("▶  Start Scan")

    def _on_scan_failed(self, msg: str):
        self._status_label.setText(f"Stopped: {msg}")
        self._start_btn.setText("▶  Start Scan")
