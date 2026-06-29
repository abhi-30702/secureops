import json
import threading
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Scan
from workers.base_tool import ToolRunner, CancelledError
from workers.tools import subfinder, httpx, nuclei


class BatchScanWorker(QThread):
    company_started    = pyqtSignal(str, int)    # (company_name, index)
    finding_discovered = pyqtSignal(object)       # Finding dataclass
    tool_log           = pyqtSignal(str)
    company_complete   = pyqtSignal(str, int)    # (company_name, findings_count)
    batch_complete     = pyqtSignal(int, int)    # (companies_scanned, total_findings)
    error_occurred     = pyqtSignal(str, str)    # (company_name, error)

    def __init__(self, companies: list[dict], db: DB, parent=None):
        super().__init__(parent)
        self._companies = companies
        self._db = db
        self._stop = threading.Event()
        # Scan ids created during the run, in order — used to assemble the
        # consolidated cross-company report after the batch completes.
        self.scan_ids: list[int] = []

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        total_findings = 0
        scanned = 0

        for i, company in enumerate(self._companies):
            if self._stop.is_set():
                break

            try:
                domains = json.loads(company.get("domains", "[]"))
            except Exception:
                domains = []
            if not domains:
                continue

            domain = domains[0]
            self.company_started.emit(company["name"], i)
            self.tool_log.emit(f"[batch] scanning {company['name']} ({domain})")

            # Isolate each company: a failure scanning one (DB error, unexpected
            # bug) must never abort the rest of the batch. 9-company scope means
            # one bad company can't take down the whole run.
            try:
                scan = Scan(
                    id=None,
                    client_id=company.get("id"),
                    target=domain,
                    status="running",
                    started_at=datetime.now(timezone.utc).isoformat(),
                    finished_at=None,
                )
                scan_id = self._db.insert_scan(scan)
                self.scan_ids.append(scan_id)

                count = self._run_company(domain, scan_id)
                self._db.update_scan_status(scan_id, "complete", datetime.now(timezone.utc).isoformat())
                self.company_complete.emit(company["name"], count)
                total_findings += count
                scanned += 1
            except CancelledError:
                break
            except Exception as exc:
                self.error_occurred.emit(company["name"], str(exc))

        self.batch_complete.emit(scanned, total_findings)

    def _run_company(self, domain: str, scan_id: int) -> int:
        runner = ToolRunner(self._stop)
        count = 0

        try:
            host_objs = subfinder.run(domain, runner, self._db, scan_id)
            hosts = [h.subdomain for h in host_objs if h.subdomain]
            if not hosts:
                hosts = [domain]
        except Exception as exc:
            self.error_occurred.emit(domain, f"subfinder: {exc}")
            hosts = [domain]

        try:
            live_objs = httpx.run(hosts, runner, self._db, scan_id)
            urls = [h.url for h in live_objs if h.url]
        except Exception as exc:
            self.error_occurred.emit(domain, f"httpx: {exc}")
            urls = []

        if not urls:
            return count

        try:
            finding_objs = nuclei.run(urls, runner, self._db, scan_id)
            for f in finding_objs:
                self.finding_discovered.emit(f)
                count += 1
        except CancelledError:
            pass
        except Exception as exc:
            self.error_occurred.emit(domain, f"nuclei: {exc}")

        return count
