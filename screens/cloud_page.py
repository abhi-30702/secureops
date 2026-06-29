from datetime import datetime, timezone
from types import SimpleNamespace

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSplitter,
    QPlainTextEdit, QFileDialog, QFormLayout,
)

from db import DB
from models import Scan
from workers.cloud_worker import CloudWorker
from screens.widgets.finding_cards import FindingCards
from screens.widgets.company_selector import CompanySelector
from screens.widgets import theme as T
from screens.widgets.components import PageHeader, Card, PrimaryButton, SecondaryButton


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
        self._start_btn = None
        self._status_label: QLabel | None = None
        self._finding_cards: FindingCards | None = None
        self._terminal: QPlainTextEdit | None = None
        self._company_selector: CompanySelector | None = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        layout.setSpacing(T.SP_LG)

        header = PageHeader("Cloud Audit", "Detect AWS & GCP misconfigurations")
        self._start_btn = PrimaryButton("▶  Start Audit", "Audit the configured providers")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)
        header.add_action(self._start_btn)
        layout.addWidget(header)

        if self._db:
            self._company_selector = CompanySelector(db=self._db)
            self._company_selector.company_selected.connect(self._on_company_selected)
            layout.addWidget(self._company_selector)

        # Provider config cards, side by side
        providers_row = QHBoxLayout()
        providers_row.setSpacing(T.SP_LG)

        aws_card = Card("Amazon Web Services")
        aws_form = QFormLayout()
        aws_form.setSpacing(T.SP_SM)
        self._aws_profile = QLineEdit()
        self._aws_profile.setPlaceholderText("default (blank to skip AWS)")
        self._aws_region = QLineEdit()
        self._aws_region.setPlaceholderText("us-east-1")
        aws_form.addRow("Profile", self._aws_profile)
        aws_form.addRow("Region", self._aws_region)
        aws_card.add_layout(aws_form)
        providers_row.addWidget(aws_card, stretch=1)

        gcp_card = Card("Google Cloud Platform")
        gcp_form = QFormLayout()
        gcp_form.setSpacing(T.SP_SM)
        self._gcp_project = QLineEdit()
        self._gcp_project.setPlaceholderText("my-project-123 (blank to skip GCP)")
        creds_row = QHBoxLayout()
        creds_row.setSpacing(T.SP_SM)
        self._gcp_creds = QLineEdit()
        self._gcp_creds.setPlaceholderText("/path/to/service-account.json (optional)")
        browse_btn = SecondaryButton("Browse…", "Choose a service-account JSON file")
        browse_btn.clicked.connect(self._browse_creds)
        creds_row.addWidget(self._gcp_creds, stretch=1)
        creds_row.addWidget(browse_btn)
        gcp_form.addRow("Project ID", self._gcp_project)
        gcp_form.addRow("Creds JSON", creds_row)
        gcp_card.add_layout(gcp_form)
        providers_row.addWidget(gcp_card, stretch=1)

        layout.addLayout(providers_row)

        self._status_label = QLabel(
            "Idle — configure at least one provider and click Start Audit"
        )
        self._status_label.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")
        layout.addWidget(self._status_label)

        # Findings + terminal
        findings_card = Card("Findings")
        self._finding_cards = FindingCards()
        findings_card.add(self._finding_cards, stretch=1)

        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setStyleSheet(
            f"background: {T.TERMINAL_BG}; color: {T.TERMINAL_TXT}; "
            f"font-family: {T.FONT_MONO}; font-size: {T.FS_SMALL}px; "
            f"border-radius: {T.RADIUS_MD}px;"
        )

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(findings_card)
        splitter.addWidget(self._terminal)
        splitter.setSizes([520, 160])
        layout.addWidget(splitter, stretch=1)

    # ── slots ─────────────────────────────────────────────────────────────────

    def _on_company_selected(self, company: dict) -> None:
        self._aws_profile.setText(company.get("aws_profile", ""))
        self._gcp_project.setText(company.get("gcp_project", ""))

    def _on_start_stop(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        aws_profile = self._aws_profile.text().strip()
        aws_region = self._aws_region.text().strip()
        gcp_project = self._gcp_project.text().strip()
        gcp_creds = self._gcp_creds.text().strip()

        if not aws_profile and not aws_region and not gcp_project:
            self._status_label.setText("Error: configure at least one provider")
            self._status_label.setStyleSheet(f"color: {T.CRITICAL}; font-size: {T.FS_SMALL}px;")
            return

        target_parts = []
        if aws_profile or aws_region:
            target_parts.append(f"aws:{aws_profile or aws_region}")
        if gcp_project:
            target_parts.append(f"gcp:{gcp_project}")
        target = ",".join(target_parts) or "cloud"

        scan = Scan(
            id=None, client_id=1, target=target, status="running",
            started_at=datetime.now(timezone.utc).isoformat(), finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._finding_cards.reset()
        self._terminal.clear()
        self._status_label.setText("Running cloud audit…")
        self._status_label.setStyleSheet(f"color: {T.ACCENT}; font-size: {T.FS_SMALL}px;")

        worker = CloudWorker(
            scan_id=self._scan_id, db=self._db,
            aws_profile=aws_profile, aws_region=aws_region,
            gcp_project=gcp_project, gcp_creds_file=gcp_creds,
        )
        worker.finding_discovered.connect(self._on_finding)
        worker.tool_log.connect(self._on_log)
        worker.scan_complete.connect(self._on_complete)
        worker.error_occurred.connect(self._on_error)
        worker.finished.connect(self._on_worker_finished)

        self._start_btn.setText("■  Stop")
        self._worker = worker
        worker.start()

    def _on_worker_finished(self):
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        self._start_btn.setText("▶  Start Audit")
        self._start_btn.setEnabled(True)

    def _on_finding(self, finding: dict):
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
        self._status_label.setStyleSheet(f"color: {T.SUCCESS}; font-size: {T.FS_SMALL}px;")

    def _on_error(self, tool: str, msg: str):
        self._terminal.appendPlainText(f"[error] {tool}: {msg}")

    def _browse_creds(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select GCP Service Account JSON", "",
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            self._gcp_creds.setText(path)
