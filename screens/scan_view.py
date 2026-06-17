from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit,
    QFileDialog,
)
from screens.widgets.pipeline_tracker import PipelineTracker
from screens.widgets.attack_graph import AttackGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards
from screens.widgets.company_selector import CompanySelector
from screens.widgets.theme import TXT, TXT3, CARD


class ScanViewScreen(QWidget):
    scan_ready = pyqtSignal(int)

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._mode = "scan"
        self._target_input: QLineEdit | None = None
        self._scan_mode_btn: QPushButton | None = None
        self._log_mode_btn: QPushButton | None = None
        self._browse_btn: QPushButton | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._log_status_label: QLabel | None = None
        self._pipeline_panel: PipelineTracker | None = None
        self._attack_graph_panel: AttackGraph | None = None
        self._severity_panel: SeverityRings | None = None
        self._finding_cards_panel: FindingCards | None = None
        self._terminal_panel: QPlainTextEdit | None = None
        self._worker = None
        self._batch_worker = None
        self._scan_id: int | None = None
        self._company_selector: CompanySelector | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        if self._db:
            self._company_selector = CompanySelector(db=self._db)
            self._company_selector.company_selected.connect(self._on_company_selected)
            layout.addWidget(self._company_selector)

        top_bar = QHBoxLayout()

        self._scan_mode_btn = QPushButton("Scan Target")
        self._scan_mode_btn.setCheckable(True)
        self._scan_mode_btn.setChecked(True)
        self._scan_mode_btn.setProperty("active", "true")
        self._scan_mode_btn.setFixedWidth(110)
        self._scan_mode_btn.clicked.connect(lambda: self._set_mode("scan"))

        self._log_mode_btn = QPushButton("Analyse Logs")
        self._log_mode_btn.setCheckable(True)
        self._log_mode_btn.setChecked(False)
        self._log_mode_btn.setProperty("active", "false")
        self._log_mode_btn.setFixedWidth(110)
        self._log_mode_btn.clicked.connect(lambda: self._set_mode("logs"))

        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")

        self._browse_btn = QPushButton("Browse")
        self._browse_btn.setFixedWidth(72)
        self._browse_btn.setVisible(False)
        self._browse_btn.clicked.connect(self._on_browse)

        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.setToolTip("Enter a target and click to scan" if self._db else "DB not initialised")
        self._start_btn.clicked.connect(self._on_start_cancel)

        self._batch_btn = QPushButton("⚡ Scan All")
        self._batch_btn.setEnabled(self._db is not None)
        self._batch_btn.setToolTip("Run subfinder→httpx→nuclei across all registered companies")
        self._batch_btn.clicked.connect(self._on_batch_scan)

        top_bar.addWidget(self._scan_mode_btn)
        top_bar.addWidget(self._log_mode_btn)
        top_bar.addWidget(self._target_input, stretch=1)
        top_bar.addWidget(self._browse_btn)
        top_bar.addWidget(self._batch_btn)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"color: {TXT3}; font-size: 11px;")
        layout.addWidget(self._status_label)

        self._log_status_label = QLabel("")
        self._log_status_label.setStyleSheet(f"color: {TXT3}; font-size: 11px;")
        self._log_status_label.setVisible(False)
        layout.addWidget(self._log_status_label)

        self._pipeline_panel = PipelineTracker()
        self._attack_graph_panel = AttackGraph()
        self._attack_graph_panel.reset()
        self._severity_panel = SeverityRings()
        self._finding_cards_panel = FindingCards()

        self._terminal_panel = QPlainTextEdit()
        self._terminal_panel.setReadOnly(True)
        self._terminal_panel.setObjectName("panel")
        self._terminal_panel.setStyleSheet(
            f"font-family: monospace; font-size: 11px; color: {CARD}; background-color: #2A1F45;"
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

    def _on_batch_scan(self) -> None:
        from workers.batch_scan_worker import BatchScanWorker
        companies = self._db.get_companies() if self._db else []
        if not companies:
            self._status_label.setText("No companies registered.")
            return
        self._batch_worker = BatchScanWorker(companies=companies, db=self._db)
        self._batch_worker.finding_discovered.connect(self._finding_cards_panel.add_finding)
        self._batch_worker.finding_discovered.connect(self._severity_panel.add_finding)
        self._batch_worker.tool_log.connect(self._log)
        self._batch_worker.company_started.connect(
            lambda name, idx: self._status_label.setText(f"Scanning {name}…")
        )
        self._batch_worker.batch_complete.connect(
            lambda n, total: self._status_label.setText(
                f"Batch complete — {n} companies, {total} findings"
            )
        )
        self._batch_worker.finished.connect(self._batch_worker.deleteLater)
        self._batch_btn.setEnabled(False)
        self._batch_worker.batch_complete.connect(lambda *_: self._batch_btn.setEnabled(True))
        self._batch_worker.start()

    def _on_company_selected(self, company: dict) -> None:
        import json
        try:
            domains = json.loads(company.get("domains", "[]"))
            if domains:
                self._target_input.setText(domains[0])
        except Exception:
            pass

    def _set_mode(self, mode: str):
        self._mode = mode
        is_scan = mode == "scan"
        self._scan_mode_btn.setProperty("active", "true" if is_scan else "false")
        self._log_mode_btn.setProperty("active", "false" if is_scan else "true")
        self._scan_mode_btn.style().unpolish(self._scan_mode_btn)
        self._scan_mode_btn.style().polish(self._scan_mode_btn)
        self._log_mode_btn.style().unpolish(self._log_mode_btn)
        self._log_mode_btn.style().polish(self._log_mode_btn)
        self._target_input.setText("")
        self._target_input.setPlaceholderText(
            "Target domain or IP (e.g. example.com)" if is_scan
            else "Path to log file (e.g. /var/log/auth.log)"
        )
        self._browse_btn.setVisible(not is_scan)
        self._pipeline_panel.setVisible(is_scan)
        self._log_status_label.setVisible(not is_scan)
        self._start_btn.setText("▶  Start Scan" if is_scan else "▶  Analyse")

    def _on_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select log file", "/var/log",
            "Log files (*.log *.txt *);;All files (*)"
        )
        if path:
            self._target_input.setText(path)

    def _on_start_cancel(self):
        if self._worker and self._worker.isRunning():
            if hasattr(self._worker, "cancel"):
                self._worker.cancel()
            self._start_btn.setEnabled(False)
            self._start_btn.setText("Cancelling…")
            return

        target = self._target_input.text().strip()
        if not target:
            self._status_label.setText(
                "Enter a target first." if self._mode == "scan" else "Select a log file first."
            )
            return

        from models import Scan

        scan = Scan(
            id=None,
            client_id=None,
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._severity_panel.reset()
        self._finding_cards_panel.reset()
        self._terminal_panel.clear()

        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None

        if self._mode == "scan":
            from workers.scan_worker import ScanWorker
            self._pipeline_panel.reset()
            self._attack_graph_panel.reset()
            self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)
            self._worker.tool_started.connect(self._pipeline_panel.on_tool_started)
            self._worker.tool_finished.connect(self._pipeline_panel.on_tool_finished)
            self._worker.tool_failed.connect(self._pipeline_panel.on_tool_failed)
            self._worker.scan_complete.connect(self._pipeline_panel.on_scan_complete)
            self._worker.host_found.connect(self._attack_graph_panel.add_host)
            self._worker.finding_found.connect(self._attack_graph_panel.add_finding)
            self._worker.scan_complete.connect(self._attack_graph_panel.on_scan_complete)
            self._worker.tool_started.connect(self._on_tool_started)
            self._worker.tool_finished.connect(self._on_tool_finished)
            self._worker.tool_failed.connect(self._on_tool_failed_log)
        else:
            from workers.log_analyzer import LogAnalyzerWorker
            self._log_status_label.setText("Detecting format…")
            self._worker = LogAnalyzerWorker(path=target, scan_id=self._scan_id, db=self._db)
            self._worker.log_line.connect(self._on_log_status_update)

        self._worker.finding_found.connect(self._severity_panel.add_finding)
        self._worker.scan_complete.connect(self._severity_panel.on_scan_complete)
        self._worker.finding_found.connect(self._finding_cards_panel.add_finding)
        self._worker.scan_complete.connect(self._finding_cards_panel.on_scan_complete)
        self._worker.log_line.connect(self._log)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_failed.connect(self._on_scan_failed)

        self._start_btn.setText("■  Cancel")
        self._worker.start()

    def _log(self, line: str):
        self._terminal_panel.appendPlainText(line)

    def _on_tool_started(self, name: str):
        self._status_label.setText(f"{name} — running…")

    def _on_tool_finished(self, name: str, count: int):
        self._status_label.setText(f"{name} — {count} items")

    def _on_tool_failed_log(self, name: str, msg: str):
        self._log(f"[FAILED] {name}: {msg}")

    def _on_log_status_update(self, line: str):
        if "detected format" in line:
            self._log_status_label.setText("Running rules…")
        elif "rules complete" in line:
            self._log_status_label.setText("Enriching with AI Advisor…")

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

    def start_scan(self, target: str) -> None:
        """Programmatically trigger a scan. No-op if already running or no DB."""
        if self._worker and self._worker.isRunning():
            return
        if not self._db:
            return
        self._target_input.setText(target)
        # Defer scan start to next event-loop tick so callers can read _target_input synchronously
        QTimer.singleShot(0, self._on_start_cancel)
