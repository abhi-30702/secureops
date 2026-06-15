from datetime import datetime, timezone

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
)

from db import DB
from models import Scan
from workers.osint_worker import OsintWorker
from screens.widgets.company_selector import CompanySelector

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
BG      = "#FEFACD"
ACCENT  = "#5F4A8B"
TEXT    = "#2A1F45"
HOVER   = "#8B75C2"
SURFACE = "#FFFEF2"
BORDER  = "#C8B8E8"

TYPE_COLORS = {
    "email":     "#5F4A8B",
    "subdomain": "#5A7A9B",
    "ip":        "#B38B00",
    "url":       "#C94A62",
    "name":      "#00805A",
}

_DEFAULT_SOURCES = (
    "crtsh,dnsdumpster,rapiddns,certspotter,hackertarget,commoncrawl"
)

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
    background: #9B8FC2;
    color: #FFFEF2;
}}
QTableWidget {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    gridline-color: {BORDER};
    alternate-background-color: #FDF8DC;
}}
QHeaderView::section {{
    background: {ACCENT};
    color: {BG};
    padding: 4px;
    border: none;
    font-weight: bold;
}}
QPlainTextEdit {{
    background: #1A1030;
    color: #C8B8E8;
    border: 1px solid {BORDER};
    border-radius: 4px;
}}
"""


class OsintPage(QWidget):
    """OSINT Intelligence screen — runs OsintWorker and streams results."""

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db: DB | None = db
        self._worker: OsintWorker | None = None
        self._scan_id: int | None = None

        self._domain_input: QLineEdit | None = None
        self._sources_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._table: QTableWidget | None = None
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
        header = QLabel("OSINT Intelligence")
        header.setObjectName("header")
        layout.addWidget(header)

        if self._db:
            self._company_selector = CompanySelector(db=self._db)
            self._company_selector.company_selected.connect(self._on_company_selected)
            layout.addWidget(self._company_selector)

        # Top bar
        top_bar = QHBoxLayout()
        top_bar.setSpacing(6)

        top_bar.addWidget(QLabel("Domain:"))
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("target-domain.com")
        top_bar.addWidget(self._domain_input, stretch=1)

        top_bar.addSpacing(8)
        top_bar.addWidget(QLabel("Sources:"))
        self._sources_input = QLineEdit()
        self._sources_input.setText(_DEFAULT_SOURCES)
        self._sources_input.setMinimumWidth(320)
        top_bar.addWidget(self._sources_input, stretch=2)

        top_bar.addSpacing(8)
        self._start_btn = QPushButton("▶ Start Scan")
        self._start_btn.setObjectName("start_btn")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)
        top_bar.addWidget(self._start_btn)

        layout.addLayout(top_bar)

        # Status label
        self._status_label = QLabel(
            "Idle — enter a domain and click Start Scan"
        )
        self._status_label.setStyleSheet(f"color: {TEXT}; font-size: 11px;")
        layout.addWidget(self._status_label)

        # Table
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setAlternatingRowColors(True)

        # Terminal
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setFont(QFont("Monospace", 9))
        self._terminal.setMaximumHeight(150)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._table)
        splitter.addWidget(self._terminal)
        splitter.setSizes([500, 150])

        layout.addWidget(splitter, stretch=1)

    # ------------------------------------------------------------------
    # Slot: start / stop button
    # ------------------------------------------------------------------

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
            # Stop running scan
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        # Validate domain
        domain = self._domain_input.text().strip()
        if not domain:
            self._status_label.setText("Error: domain is required")
            self._status_label.setStyleSheet(
                "color: #C94A62; font-size: 11px;"
            )
            return

        sources = self._sources_input.text().strip() or _DEFAULT_SOURCES

        # Insert scan record
        scan = Scan(
            id=None,
            client_id=1,
            target=domain,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        # Reset UI
        self._table.setRowCount(0)
        self._terminal.clear()
        self._status_label.setText(f"Scanning {domain}…")
        self._status_label.setStyleSheet(
            f"color: {ACCENT}; font-size: 11px;"
        )

        # Create and wire worker
        self._worker = OsintWorker(
            domain=domain,
            scan_id=self._scan_id,
            db=self._db,
            sources=sources,
        )
        self._worker.item_found.connect(self._on_item_found)
        self._worker.log_line.connect(self._on_log_line)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

        self._start_btn.setText("■ Stop")

    # ------------------------------------------------------------------
    # Worker signal handlers
    # ------------------------------------------------------------------

    def _on_worker_finished(self):
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        self._start_btn.setText("▶ Start Scan")
        self._start_btn.setEnabled(True)

    def _on_item_found(self, item: dict):
        row = self._table.rowCount()
        self._table.insertRow(row)

        item_type = item.get("item_type", "")
        color = TYPE_COLORS.get(item_type, TEXT)

        type_cell = QTableWidgetItem(item_type)
        type_cell.setForeground(QColor(color))
        self._table.setItem(row, 0, type_cell)
        self._table.setItem(row, 1, QTableWidgetItem(item.get("value", "")))
        self._table.setItem(row, 2, QTableWidgetItem(item.get("source", "")))

    def _on_log_line(self, line: str):
        self._terminal.appendPlainText(line)

    def _on_complete(self, _: int, count: int):
        self._status_label.setText(f"Complete — {count} items found")
        self._status_label.setStyleSheet(
            "color: #00805A; font-size: 11px;"
        )

    def _on_failed(self, msg: str):
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet(
            "color: #C94A62; font-size: 11px;"
        )
        self._scan_id = None
