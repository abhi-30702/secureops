"""Scan history — a browsable table of every past scan.

Reads all scans from SQLite (newest first), shows target / status / timing /
finding counts, and lets the user re-open any scan in the Report view by
double-clicking (or selecting + View Report). Read-only: it never mutates a
scan, so reviewing history is always safe.
"""
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView,
)

from screens.widgets import theme as T
from screens.widgets.components import (
    PageHeader, Card, SecondaryButton, PrimaryButton,
)

_COLUMNS = ["Target", "Status", "Started", "Finished", "Findings", "Top severity"]
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


class HistoryScreen(QWidget):
    """Table of past scans; emits `scan_selected(scan_id)` to open a report."""

    scan_selected = pyqtSignal(int)

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._scan_ids: list[int] = []
        self._table: QTableWidget | None = None
        self._empty_label: QLabel | None = None
        self._setup_ui()
        self.refresh()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        layout.setSpacing(T.SP_LG)

        header = PageHeader("Scan History", "Review and re-open past scans")
        self._refresh_btn = SecondaryButton("↻  Refresh", "Reload the scan list")
        self._refresh_btn.clicked.connect(self.refresh)
        self._open_btn = PrimaryButton("View Report", "Open the selected scan")
        self._open_btn.clicked.connect(self._open_selected)
        self._open_btn.setEnabled(False)
        header.add_action(self._refresh_btn)
        header.add_action(self._open_btn)
        layout.addWidget(header)

        card = Card()
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.setSortingEnabled(True)
        self._table.setCursor(Qt.CursorShape.PointingHandCursor)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for c in range(1, len(_COLUMNS)):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        self._table.doubleClicked.connect(self._open_selected)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.setStyleSheet(
            f"QTableWidget {{ background: {T.CARD}; border: none; color: {T.TXT};"
            f" font-size: {T.FS_SMALL}px; gridline-color: {T.BORDER}; }}"
            f"QTableWidget::item {{ padding: 6px 8px; }}"
            f"QTableWidget::item:selected {{ background: {T.ACCENT_SOFT}; color: {T.TXT}; }}"
            f"QHeaderView::section {{ background: {T.BG_ALT}; color: {T.TXT3};"
            f" border: none; border-bottom: 1px solid {T.BORDER}; padding: 6px 8px;"
            f" font-weight: bold; }}"
        )
        card.add(self._table, stretch=1)

        self._empty_label = QLabel("No scans yet — run a scan to build history.")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(
            f"color: {T.TXT3}; font-size: {T.FS_SMALL}px; padding: {T.SP_XL}px;"
        )
        card.add(self._empty_label)

        layout.addWidget(card, stretch=1)

    def refresh(self) -> None:
        if not self._table:
            return
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        self._scan_ids = []
        scans = self._db.query_all_scans() if self._db else []
        counts = self._db.finding_counts_by_scan() if self._db else {}

        for scan in scans:
            sev = counts.get(scan.id, {})
            total = sum(sev.values())
            top = next((s for s in _SEV_ORDER if sev.get(s)), "—")
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._scan_ids.append(scan.id)
            self._set_cell(row, 0, scan.target or "—")
            self._set_cell(row, 1, (scan.status or "").title(), self._status_color(scan.status))
            self._set_cell(row, 2, self._fmt_ts(scan.started_at))
            self._set_cell(row, 3, self._fmt_ts(scan.finished_at) if scan.finished_at else "—")
            self._set_cell(row, 4, str(total), align=Qt.AlignmentFlag.AlignCenter)
            self._set_cell(
                row, 5, top.title() if top != "—" else "—",
                T.SEVERITY_COLORS.get(top) if top != "—" else None,
            )

        self._table.setSortingEnabled(True)
        has_rows = bool(self._scan_ids)
        self._table.setVisible(has_rows)
        self._empty_label.setVisible(not has_rows)
        self._open_btn.setEnabled(False)

    def _set_cell(self, row, col, text, color=None, align=None):
        item = QTableWidgetItem(text)
        if color:
            from PyQt6.QtGui import QColor
            item.setForeground(QColor(color))
        if align is not None:
            item.setTextAlignment(align | Qt.AlignmentFlag.AlignVCenter)
        else:
            item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._table.setItem(row, col, item)

    def _on_selection_changed(self):
        self._open_btn.setEnabled(bool(self._table.selectionModel().selectedRows()))

    def _open_selected(self, *args):
        row = self._table.currentRow()
        if 0 <= row < len(self._scan_ids):
            self.scan_selected.emit(self._scan_ids[row])

    @staticmethod
    def _status_color(status: str) -> str:
        s = (status or "").lower()
        if s in ("complete", "completed", "done"):
            return T.SUCCESS
        if s in ("failed", "error", "cancelled"):
            return T.CRITICAL
        if s in ("running", "scanning"):
            return T.LOW
        return T.TXT2

    @staticmethod
    def _fmt_ts(ts: str) -> str:
        if not ts:
            return "—"
        # ISO 8601 → "YYYY-MM-DD  HH:MM"
        t = ts.replace("T", "  ")
        return t[:16] if len(t) >= 16 else t
