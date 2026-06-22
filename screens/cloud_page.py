from datetime import datetime, timezone
from types import SimpleNamespace

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QSplitter,
    QPlainTextEdit, QFileDialog,
)

from db import DB
from models import Scan
from workers.cloud_worker import CloudWorker
from screens.widgets.finding_cards import FindingCards
from screens.widgets.company_selector import CompanySelector
from screens.widgets.theme import BG, ACCENT, TXT as TEXT, CARD as SURFACE, BORDER, ACCENT_H as HOVER, CRITICAL, SUCCESS

_QSS = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: "DM Sans", sans-serif;
    font-size: 12px;
}}
QLabel#header {{
    color: {ACCENT};
    font-size: 18px;
    font-weight: bold;
}}
QLineEdit {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 8px;
    color: {TEXT};
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT};
}}
QPushButton#start_btn {{
    background: {ACCENT};
    color: {BG};
    border-radius: 4px;
    padding: 4px 14px;
    font-weight: bold;
}}
QPushButton#start_btn:hover {{
    background: {HOVER};
}}
QPushButton#start_btn:disabled {{
    background: {HOVER};
    color: {SURFACE};
}}
QPushButton#browse_btn {{
    background: {SURFACE};
    color: {ACCENT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 10px;
}}
QPushButton#browse_btn:hover {{
    background: {BORDER};
}}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    margin-top: 8px;
    padding: 8px;
    font-weight: bold;
    color: {ACCENT};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 8px;
}}
QPlainTextEdit {{
    background: #1A1030;
    color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 4px;
}}
"""


class CloudPage(QWidget):
    """Cloud Audit screen — runs CloudWorker and streams AWS/GCP findings."""

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db: DB | None = db
        self._worker: CloudWorker | None = None
        self._scan_id: int | None = None

        self._aws_profile: QLineEdit | None = None
        self._aws_region: QLineEdit | None = None
        self._gcp_project: QLineEdit | None = None
        self._gcp_creds: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._finding_cards: FindingCards | None = None
        self._terminal: QPlainTextEdit | None = None
        self._company_selector: CompanySelector | None = None

        self._setup_ui()
        self.setStyleSheet(_QSS)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Header
        header = QLabel("Cloud Audit")
        header.setObjectName("header")
        layout.addWidget(header)

        if self._db:
            self._company_selector = CompanySelector(db=self._db)
            self._company_selector.company_selected.connect(self._on_company_selected)
            layout.addWidget(self._company_selector)

        # AWS group
        aws_group = QGroupBox("AWS")
        aws_layout = QVBoxLayout(aws_group)
        aws_layout.setSpacing(6)

        aws_profile_row = QHBoxLayout()
        aws_profile_row.addWidget(QLabel("Profile:"))
        self._aws_profile = QLineEdit()
        self._aws_profile.setPlaceholderText(
            "default (leave blank to skip AWS)"
        )
        aws_profile_row.addWidget(self._aws_profile, stretch=1)
        aws_layout.addLayout(aws_profile_row)

        aws_region_row = QHBoxLayout()
        aws_region_row.addWidget(QLabel("Region:"))
        self._aws_region = QLineEdit()
        self._aws_region.setPlaceholderText("us-east-1")
        aws_region_row.addWidget(self._aws_region, stretch=1)
        aws_layout.addLayout(aws_region_row)

        layout.addWidget(aws_group)

        # GCP group
        gcp_group = QGroupBox("GCP")
        gcp_layout = QVBoxLayout(gcp_group)
        gcp_layout.setSpacing(6)

        gcp_project_row = QHBoxLayout()
        gcp_project_row.addWidget(QLabel("Project ID:"))
        self._gcp_project = QLineEdit()
        self._gcp_project.setPlaceholderText(
            "my-project-123 (leave blank to skip GCP)"
        )
        gcp_project_row.addWidget(self._gcp_project, stretch=1)
        gcp_layout.addLayout(gcp_project_row)

        gcp_creds_row = QHBoxLayout()
        gcp_creds_row.addWidget(QLabel("Creds JSON:"))
        self._gcp_creds = QLineEdit()
        self._gcp_creds.setPlaceholderText(
            "/path/to/service-account.json (optional)"
        )
        gcp_creds_row.addWidget(self._gcp_creds, stretch=1)
        browse_btn = QPushButton("Browse…")
        browse_btn.setObjectName("browse_btn")
        browse_btn.clicked.connect(self._browse_creds)
        gcp_creds_row.addWidget(browse_btn)
        gcp_layout.addLayout(gcp_creds_row)

        layout.addWidget(gcp_group)

        # Start button
        self._start_btn = QPushButton("▶ Start Audit")
        self._start_btn.setObjectName("start_btn")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)
        layout.addWidget(self._start_btn)

        # Status label
        self._status_label = QLabel(
            "Idle — configure at least one provider and click Start Audit"
        )
        self._status_label.setStyleSheet(f"color: {TEXT}; font-size: 11px;")
        layout.addWidget(self._status_label)

        # FindingCards + terminal in a vertical splitter
        self._finding_cards = FindingCards()
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setFont(QFont("Monospace", 9))
        self._terminal.setMaximumHeight(150)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._finding_cards)
        splitter.addWidget(self._terminal)
        splitter.setSizes([500, 150])

        layout.addWidget(splitter, stretch=1)

    # ------------------------------------------------------------------
    # Slot: start / stop button
    # ------------------------------------------------------------------

    def _on_company_selected(self, company: dict) -> None:
        self._aws_profile.setText(company.get("aws_profile", ""))
        self._gcp_project.setText(company.get("gcp_project", ""))

    def _on_start_stop(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        # Validate — at least one provider must be configured
        aws_profile = self._aws_profile.text().strip()
        aws_region  = self._aws_region.text().strip()
        gcp_project = self._gcp_project.text().strip()
        gcp_creds   = self._gcp_creds.text().strip()

        if not aws_profile and not aws_region and not gcp_project:
            self._status_label.setText(
                "Error: configure at least one provider"
            )
            self._status_label.setStyleSheet(
                f"color: {CRITICAL}; font-size: 11px;"
            )
            return

        # Build a readable target string for the scan record
        target_parts = []
        if aws_profile or aws_region:
            target_parts.append(f"aws:{aws_profile or aws_region}")
        if gcp_project:
            target_parts.append(f"gcp:{gcp_project}")
        target = ",".join(target_parts) or "cloud"

        # Insert scan record
        scan = Scan(
            id=None,
            client_id=1,
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        # Reset UI
        self._finding_cards.reset()
        self._terminal.clear()
        self._status_label.setText("Running cloud audit…")
        self._status_label.setStyleSheet(
            f"color: {ACCENT}; font-size: 11px;"
        )

        # Create and wire worker
        worker = CloudWorker(
            scan_id=self._scan_id,
            db=self._db,
            aws_profile=aws_profile,
            aws_region=aws_region,
            gcp_project=gcp_project,
            gcp_creds_file=gcp_creds,
        )
        worker.finding_discovered.connect(self._on_finding)
        worker.tool_log.connect(self._on_log)
        worker.scan_complete.connect(self._on_complete)
        worker.error_occurred.connect(self._on_error)
        worker.finished.connect(self._on_worker_finished)

        self._start_btn.setText("■ Stop")
        self._worker = worker
        worker.start()

    # ------------------------------------------------------------------
    # Worker signal handlers
    # ------------------------------------------------------------------

    def _on_worker_finished(self):
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        self._start_btn.setText("▶ Start Audit")
        self._start_btn.setEnabled(True)

    def _on_finding(self, finding: dict):
        """Convert the emitted dict to a namespace so FindingCards can use
        attribute access (.severity, .title, .tool, .description)."""
        ns = SimpleNamespace(
            title=finding.get("title", ""),
            tool=finding.get("tool", "cloud_auditor"),
            severity=finding.get("severity", "info"),
            description=finding.get("description", ""),
        )
        self._finding_cards.add_finding(ns)

    def _on_log(self, line: str):
        self._terminal.appendPlainText(line)

    def _on_complete(self, summary: dict):
        count = summary.get("total", 0)
        self._status_label.setText(f"Complete — {count} findings")
        self._status_label.setStyleSheet(
            f"color: {SUCCESS}; font-size: 11px;"
        )

    def _on_error(self, tool: str, msg: str):
        self._terminal.appendPlainText(f"[error] {tool}: {msg}")

    # ------------------------------------------------------------------
    # File browser for GCP credentials
    # ------------------------------------------------------------------

    def _browse_creds(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select GCP Service Account JSON",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            self._gcp_creds.setText(path)
