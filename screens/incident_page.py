from datetime import datetime, timezone

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit, QFileDialog,
)

from db import DB
from models import Scan
from screens.widgets.breach_timeline import BreachTimeline
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards
from workers.incident_worker import IncidentWorker
from screens.widgets.theme import BG, ACCENT, TXT as TEXT, CARD as SURFACE, ACCENT_H as HOVER, CRITICAL, SUCCESS, TXT2
from screens.widgets import theme as T
from screens.widgets.components import PageHeader


class IncidentPage(QWidget):
    scan_ready = pyqtSignal(int)

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._worker: IncidentWorker | None = None
        self._scan_id: int | None = None

        self._log_input: QLineEdit | None = None
        self._yara_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._timeline: BreachTimeline | None = None
        self._severity_rings: SeverityRings | None = None
        self._finding_cards: FindingCards | None = None
        self._terminal: QPlainTextEdit | None = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        layout.setSpacing(T.SP_MD)

        layout.addWidget(PageHeader(
            "Incident Response", "Log analysis, IOC scan & breach timeline"
        ))

        # --- top bar ---
        top_bar = QHBoxLayout()

        self._log_input = QLineEdit()
        self._log_input.setPlaceholderText("Log file path (e.g. /var/log/auth.log)")
        browse_log_btn = QPushButton("Browse…")
        browse_log_btn.setMinimumWidth(84)
        browse_log_btn.clicked.connect(self._on_browse_log)

        self._yara_input = QLineEdit()
        self._yara_input.setPlaceholderText("Extra YARA scan path (optional)")
        self._yara_input.setFixedWidth(240)
        browse_yara_btn = QPushButton("Browse…")
        browse_yara_btn.setMinimumWidth(84)
        browse_yara_btn.clicked.connect(self._on_browse_yara)

        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)
        self._start_btn.setStyleSheet(
            f"QPushButton {{ background: {ACCENT}; color: {BG}; border-radius: 4px; padding: 4px 12px; }}"
            f"QPushButton:hover {{ background: {HOVER}; }}"
            f"QPushButton:disabled {{ background: {TXT2}; color: {SURFACE}; }}"
        )

        top_bar.addWidget(self._log_input, stretch=1)
        top_bar.addWidget(browse_log_btn)
        top_bar.addSpacing(12)
        top_bar.addWidget(self._yara_input)
        top_bar.addWidget(browse_yara_btn)
        top_bar.addSpacing(12)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        # --- status label ---
        self._status_label = QLabel("Idle — select a log file and click Start Scan")
        self._status_label.setStyleSheet(f"color: {TEXT}; font-size: 11px;")
        layout.addWidget(self._status_label)

        # --- body ---
        self._timeline = BreachTimeline()
        self._severity_rings = SeverityRings()
        self._finding_cards = FindingCards()
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setStyleSheet(
            f"background: {T.TERMINAL_BG}; color: {T.TERMINAL_TXT}; "
            f"font-family: {T.FONT_MONO}; font-size: {T.FS_SMALL}px; "
            f"border-radius: {T.RADIUS_MD}px;"
        )

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right_layout.addWidget(self._severity_rings)
        right_layout.addWidget(self._finding_cards, stretch=1)

        body_splitter = QSplitter(Qt.Orientation.Horizontal)
        body_splitter.addWidget(self._timeline)
        body_splitter.addWidget(right_panel)
        body_splitter.setSizes([600, 400])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(body_splitter)
        main_splitter.addWidget(self._terminal)
        main_splitter.setSizes([750, 150])

        layout.addWidget(main_splitter, stretch=1)

    def _on_browse_log(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Log File", "/var/log")
        if path:
            self._log_input.setText(path)

    def _on_browse_yara(self):
        path = QFileDialog.getExistingDirectory(self, "Select Extra YARA Scan Directory")
        if path:
            self._yara_input.setText(path)

    def _on_start_stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        log_path = self._log_input.text().strip()
        if not log_path:
            self._status_label.setText("Please select a log file first.")
            self._status_label.setStyleSheet(f"color: {CRITICAL}; font-size: 11px;")
            return

        scan = Scan(
            id=None, client_id=None,
            target=log_path,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._timeline.reset()
        self._severity_rings.reset()
        self._finding_cards.reset()
        self._terminal.clear()

        self._worker = IncidentWorker(
            log_path=log_path,
            scan_id=self._scan_id,
            db=self._db,
            yara_extra_path=self._yara_input.text().strip(),
        )
        self._worker.finding_found.connect(self._on_finding)
        self._worker.log_line.connect(self._terminal.appendPlainText)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

        self._start_btn.setText("■  Stop Scan")
        self._status_label.setText("Scanning…")
        self._status_label.setStyleSheet(f"color: {ACCENT}; font-size: 11px;")

    def _on_finding(self, finding):
        self._severity_rings.add_finding(finding)
        self._finding_cards.add_finding(finding)

    def _on_complete(self, _hosts: int, findings: int):
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)
        if self._worker:
            self._worker.deleteLater()
            self._worker = None
        self._status_label.setText(f"Done — {findings} findings")
        self._status_label.setStyleSheet(f"color: {SUCCESS}; font-size: 11px;")
        self._finding_cards.on_scan_complete(0, findings)
        self._severity_rings.on_scan_complete(0, findings)
        if self._scan_id is not None:
            for event in self._db.get_incident_events(self._scan_id):
                self._timeline.add_event(event)
            self.scan_ready.emit(self._scan_id)

    def _on_failed(self, msg: str):
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)
        if self._worker:
            self._worker.deleteLater()
            self._worker = None
        self._scan_id = None
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet(f"color: {CRITICAL}; font-size: 11px;")

    def _on_worker_finished(self):
        if not self._start_btn.isEnabled():
            self._start_btn.setText("▶  Start Scan")
            self._start_btn.setEnabled(True)
