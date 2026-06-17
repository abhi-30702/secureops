from datetime import datetime, timezone, timedelta
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView,
)
from db import DB


def _next_due(last_run: str | None, interval_h: int) -> str:
    if not last_run:
        return "overdue"
    try:
        last = datetime.fromisoformat(last_run)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        due = last + timedelta(hours=interval_h)
        now = datetime.now(timezone.utc)
        if due <= now:
            return "overdue"
        return due.strftime("%H:%M")
    except Exception:
        return "—"


class SchedulePanel(QWidget):
    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        hdr = QLabel("Scheduled Scans")
        hdr.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 12px;")
        layout.addWidget(hdr)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Target", "Interval", "Next Due"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table)

        self.refresh()

    def refresh(self) -> None:
        self._table.setRowCount(0)
        for sched in self._db.query_schedules():
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(sched.target))
            self._table.setItem(row, 1, QTableWidgetItem(f"{sched.interval_h}h"))
            self._table.setItem(row, 2, QTableWidgetItem(
                _next_due(sched.last_run, sched.interval_h)
            ))
