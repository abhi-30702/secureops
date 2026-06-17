from PyQt6.QtCore import QThread, pyqtSignal
from db import DB


class DeltaWorker(QThread):
    delta_ready    = pyqtSignal(str, int, int)  # target, new_count, resolved_count
    error_occurred = pyqtSignal(str)

    def __init__(self, scan_id: int, db: DB, parent=None):
        super().__init__(parent)
        self._scan_id = scan_id
        self._db = db

    def run(self) -> None:
        try:
            row = self._db._conn.execute(
                "SELECT target FROM scans WHERE id=?", (self._scan_id,)
            ).fetchone()
            if row is None:
                self.error_occurred.emit(f"scan {self._scan_id} not found")
                return
            target = row["target"]

            curr_findings = self._db.query_findings_by_scan(self._scan_id)
            curr_keys = {(f.tool, f.title, f.description) for f in curr_findings}

            prev_row = self._db._conn.execute(
                "SELECT id FROM scans WHERE target=? AND status='complete' AND id<? "
                "ORDER BY id DESC LIMIT 1",
                (target, self._scan_id),
            ).fetchone()

            if prev_row is None:
                self.delta_ready.emit(target, len(curr_keys), 0)
                return

            prev_findings = self._db.query_findings_by_scan(prev_row["id"])
            prev_keys = {(f.tool, f.title, f.description) for f in prev_findings}

            new_count      = len(curr_keys - prev_keys)
            resolved_count = len(prev_keys - curr_keys)
            self.delta_ready.emit(target, new_count, resolved_count)

        except Exception as exc:
            self.error_occurred.emit(str(exc))
