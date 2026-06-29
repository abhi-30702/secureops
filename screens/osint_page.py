from datetime import datetime, timezone

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSplitter,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
)

from db import DB
from models import Scan
from workers.osint_worker import OsintWorker
from screens.widgets.company_selector import CompanySelector
from screens.widgets import theme as T
from screens.widgets.components import PageHeader, Card, PrimaryButton

TYPE_COLORS = {
    "email":     T.ACCENT,
    "subdomain": T.TXT2,
    "ip":        T.MEDIUM,
    "url":       T.CRITICAL,
    "name":      T.SUCCESS,
}

_DEFAULT_SOURCES = "crtsh,dnsdumpster,rapiddns,certspotter,hackertarget,commoncrawl"


class OsintPage(QWidget):
    """OSINT Intelligence screen — runs OsintWorker and streams results."""

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db: DB | None = db
        self._worker: OsintWorker | None = None
        self._scan_id: int | None = None

        self._domain_input: QLineEdit | None = None
        self._sources_input: QLineEdit | None = None
        self._start_btn = None
        self._status_label: QLabel | None = None
        self._table: QTableWidget | None = None
        self._terminal: QPlainTextEdit | None = None
        self._company_selector: CompanySelector | None = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        layout.setSpacing(T.SP_LG)

        header = PageHeader("OSINT Intelligence", "Public digital-footprint discovery")
        self._start_btn = PrimaryButton("▶  Start Scan", "Harvest public intelligence")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)
        header.add_action(self._start_btn)
        layout.addWidget(header)

        if self._db:
            self._company_selector = CompanySelector(db=self._db)
            self._company_selector.company_selected.connect(self._on_company_selected)
            layout.addWidget(self._company_selector)

        # Input card
        input_card = Card()
        top_bar = QHBoxLayout()
        top_bar.setSpacing(T.SP_SM)
        domain_lbl = QLabel("Domain")
        domain_lbl.setStyleSheet(f"color: {T.TXT2}; font-size: {T.FS_SMALL}px;")
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("target-domain.com")
        sources_lbl = QLabel("Sources")
        sources_lbl.setStyleSheet(f"color: {T.TXT2}; font-size: {T.FS_SMALL}px;")
        self._sources_input = QLineEdit()
        self._sources_input.setText(_DEFAULT_SOURCES)
        self._sources_input.setMinimumWidth(300)
        top_bar.addWidget(domain_lbl)
        top_bar.addWidget(self._domain_input, stretch=1)
        top_bar.addSpacing(T.SP_SM)
        top_bar.addWidget(sources_lbl)
        top_bar.addWidget(self._sources_input, stretch=2)
        input_card.add_layout(top_bar)
        layout.addWidget(input_card)

        self._status_label = QLabel("Idle — enter a domain and click Start Scan")
        self._status_label.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")
        layout.addWidget(self._status_label)

        # Results card with table
        results_card = Card("Harvested Items")
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        results_card.add(self._table, stretch=1)

        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setStyleSheet(
            f"background: {T.TERMINAL_BG}; color: {T.TERMINAL_TXT}; "
            f"font-family: {T.FONT_MONO}; font-size: {T.FS_SMALL}px; "
            f"border-radius: {T.RADIUS_MD}px;"
        )

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(results_card)
        splitter.addWidget(self._terminal)
        splitter.setSizes([520, 160])
        layout.addWidget(splitter, stretch=1)

    # ── slots ─────────────────────────────────────────────────────────────────

    def _on_company_selected(self, company: dict) -> None:
        import json
        try:
            domains = json.loads(company.get("domains", "[]"))
            if domains:
                self._domain_input.setText(domains[0])
        except Exception:
            pass

    def _on_start_stop(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        domain = self._domain_input.text().strip()
        if not domain:
            self._status_label.setText("Error: domain is required")
            self._status_label.setStyleSheet(f"color: {T.CRITICAL}; font-size: {T.FS_SMALL}px;")
            return

        sources = self._sources_input.text().strip() or _DEFAULT_SOURCES

        scan = Scan(
            id=None, client_id=1, target=domain, status="running",
            started_at=datetime.now(timezone.utc).isoformat(), finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._table.setRowCount(0)
        self._terminal.clear()
        self._status_label.setText(f"Scanning {domain}…")
        self._status_label.setStyleSheet(f"color: {T.ACCENT}; font-size: {T.FS_SMALL}px;")

        self._worker = OsintWorker(
            domain=domain, scan_id=self._scan_id, db=self._db, sources=sources,
        )
        self._worker.item_found.connect(self._on_item_found)
        self._worker.log_line.connect(self._on_log_line)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

        self._start_btn.setText("■  Stop")

    def _on_worker_finished(self):
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)

    def _on_item_found(self, item: dict):
        row = self._table.rowCount()
        self._table.insertRow(row)
        item_type = item.get("item_type", "")
        color = TYPE_COLORS.get(item_type, T.TXT)
        type_cell = QTableWidgetItem(item_type)
        type_cell.setForeground(QColor(color))
        self._table.setItem(row, 0, type_cell)
        self._table.setItem(row, 1, QTableWidgetItem(item.get("value", "")))
        self._table.setItem(row, 2, QTableWidgetItem(item.get("source", "")))

    def _on_log_line(self, line: str):
        self._terminal.appendPlainText(line)

    def _on_complete(self, _: int, count: int):
        self._status_label.setText(f"Complete — {count} items found")
        self._status_label.setStyleSheet(f"color: {T.SUCCESS}; font-size: {T.FS_SMALL}px;")

    def _on_failed(self, msg: str):
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet(f"color: {T.CRITICAL}; font-size: {T.FS_SMALL}px;")
        self._scan_id = None
