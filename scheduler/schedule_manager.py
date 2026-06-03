from datetime import datetime, timezone
from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from db import DB


class ScheduleManager(QObject):
    scan_due = pyqtSignal(str)

    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._check)
        self._timer.start(60_000)

    def _check(self):
        now = datetime.now(timezone.utc)
        for schedule in self._db.query_schedules():
            if not schedule.enabled:
                continue
            if schedule.last_run is None:
                due = True
            else:
                try:
                    last = datetime.fromisoformat(schedule.last_run)
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    due = (now - last).total_seconds() >= schedule.interval_h * 3600
                except (ValueError, TypeError):
                    due = True
            if due:
                self._db.update_schedule(schedule.id, enabled=True,
                                         last_run=now.isoformat())
                self.scan_due.emit(schedule.target)

    def stop(self):
        self._timer.stop()
