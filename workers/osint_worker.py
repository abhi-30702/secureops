import threading
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from workers.tools import theharvester


class OsintWorker(QThread):
    item_found     = pyqtSignal(dict)        # one OSINT item per emission
    log_line       = pyqtSignal(str)         # raw terminal output line
    scan_complete  = pyqtSignal(int, int)    # (0, total_items)
    scan_failed    = pyqtSignal(str)         # error message string
    error_occurred = pyqtSignal(str, str)    # (tool_name, error_message)

    def __init__(self, domain: str, scan_id: int, db: DB,
                 sources: str = "", parent=None):
        super().__init__(parent)
        self._domain = domain
        self._scan_id = scan_id
        self._db = db
        self._sources = sources
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        # 1. Build sources string
        sources = self._sources or "crtsh,dnsdumpster,rapiddns,certspotter,hackertarget,commoncrawl"

        # 2. Check cancel before running
        if self._stop_event.is_set():
            self._db.update_scan_status(self._scan_id, "cancelled")
            return

        # 3. Run theHarvester
        output_file = f"/tmp/secureops_harvest_{self._scan_id}"
        self.log_line.emit(f"[osint] running theHarvester for {self._domain}")

        try:
            items = theharvester.run(self._domain, sources, output_file)
        except Exception as e:
            self.scan_failed.emit(str(e))
            self._db.update_scan_status(self._scan_id, "failed")
            return

        # 4. Write each item to DB, then emit
        count = 0
        for item in items:
            item["scan_id"] = self._scan_id
            item["domain"] = self._domain
            item["created_at"] = datetime.now(timezone.utc).isoformat()
            self._db.insert_osint_item(item)
            self.item_found.emit(item)
            count += 1

        # 5. Mark complete
        self._db.update_scan_status(self._scan_id, "complete")
        self.scan_complete.emit(0, count)
