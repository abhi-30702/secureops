from datetime import datetime, timezone
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit,
)
from screens.widgets.pipeline_tracker import PipelineTracker
from screens.widgets.attack_graph import AttackGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards


class ScanViewScreen(QWidget):
    scan_ready = pyqtSignal(int)

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._target_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._pipeline_panel: PipelineTracker | None = None
        self._attack_graph_panel: AttackGraph | None = None
        self._severity_panel: SeverityRings | None = None
        self._finding_cards_panel: FindingCards | None = None
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

        self._pipeline_panel = PipelineTracker()
        self._attack_graph_panel = AttackGraph()
        self._attack_graph_panel.reset()
        self._severity_panel = SeverityRings()
        self._finding_cards_panel = FindingCards()

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
            self._start_btn.setEnabled(False)
            self._start_btn.setText("Cancelling…")
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

        self._pipeline_panel.reset()
        self._attack_graph_panel.reset()
        self._severity_panel.reset()
        self._finding_cards_panel.reset()

        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None

        self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)

        self._worker.tool_started.connect(self._pipeline_panel.on_tool_started)
        self._worker.tool_finished.connect(self._pipeline_panel.on_tool_finished)
        self._worker.tool_failed.connect(self._pipeline_panel.on_tool_failed)
        self._worker.scan_complete.connect(self._pipeline_panel.on_scan_complete)

        self._worker.host_found.connect(self._attack_graph_panel.add_host)
        self._worker.finding_found.connect(self._attack_graph_panel.add_finding)
        self._worker.scan_complete.connect(self._attack_graph_panel.on_scan_complete)

        self._worker.finding_found.connect(self._severity_panel.add_finding)
        self._worker.scan_complete.connect(self._severity_panel.on_scan_complete)

        self._worker.finding_found.connect(self._finding_cards_panel.add_finding)
        self._worker.scan_complete.connect(self._finding_cards_panel.on_scan_complete)

        self._worker.tool_started.connect(self._on_tool_started)
        self._worker.tool_finished.connect(self._on_tool_finished)
        self._worker.tool_failed.connect(self._on_tool_failed_log)
        self._worker.log_line.connect(self._log)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_failed.connect(self._on_scan_failed)

        self._start_btn.setText("■  Cancel")
        self._terminal_panel.clear()
        self._worker.start()

    def _log(self, line: str):
        self._terminal_panel.appendPlainText(line)

    def _on_tool_started(self, name: str):
        self._status_label.setText(f"{name} — running…")

    def _on_tool_finished(self, name: str, count: int):
        self._status_label.setText(f"{name} — {count} items")

    def _on_tool_failed_log(self, name: str, msg: str):
        self._log(f"[FAILED] {name}: {msg}")

    def _on_scan_complete(self, hosts: int, findings: int):
        self._status_label.setText(f"Complete — {hosts} hosts, {findings} findings")
        self._start_btn.setEnabled(True)
        self._start_btn.setText("▶  Start Scan")
        if self._worker:
            self._worker.deleteLater()
            self._worker = None
        if self._scan_id is not None:
            self.scan_ready.emit(self._scan_id)

    def _on_scan_failed(self, msg: str):
        self._status_label.setText(f"Stopped: {msg}")
        self._start_btn.setEnabled(True)
        self._start_btn.setText("▶  Start Scan")
        if self._worker:
            self._worker.deleteLater()
            self._worker = None
