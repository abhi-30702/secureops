import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from workers.base_tool import ToolRunner, CancelledError
from workers.tools import subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


class ScanWorker(QThread):
    tool_started  = pyqtSignal(str)
    tool_finished = pyqtSignal(str, int)
    tool_failed   = pyqtSignal(str, str)
    host_found    = pyqtSignal(object)
    finding_found = pyqtSignal(object)
    log_line      = pyqtSignal(str)
    scan_complete = pyqtSignal(int, int)
    scan_failed   = pyqtSignal(str)

    def __init__(self, target: str, scan_id: int, db: DB, parent=None):
        super().__init__(parent)
        self._target = target
        self._scan_id = scan_id
        self._db = db
        self._cancel_event = threading.Event()

    def cancel(self):
        self._cancel_event.set()

    def run(self):
        try:
            self._execute_pipeline()
        except CancelledError:
            self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit("Cancelled")
        except Exception as exc:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit(str(exc))

    def _make_runner(self) -> ToolRunner:
        return ToolRunner(self._cancel_event)

    def _run_tool(self, name: str, fn, *args):
        self.tool_started.emit(name)
        self.log_line.emit(f"[{name}] starting...")
        try:
            results = fn(*args)
            self.tool_finished.emit(name, len(results))
            self.log_line.emit(f"[{name}] done — {len(results)} items")
            for item in results:
                if hasattr(item, "severity"):
                    self.finding_found.emit(item)
                else:
                    self.host_found.emit(item)
            return results
        except CancelledError:
            raise
        except Exception as exc:
            # Rule #2: any tool failure is isolated, never fatal to the pipeline.
            # ToolError is the expected case; catching Exception also contains
            # unexpected wrapper bugs (DB errors, parse errors, OS errors).
            self.tool_failed.emit(name, str(exc))
            self.log_line.emit(f"[{name}] failed: {exc}")
            return []

    def _execute_pipeline(self):
        runner = self._make_runner()

        if _is_ip(self._target):
            ips = [self._target]
        else:
            subdomains_hosts = self._run_tool("subfinder", subfinder.run, self._target, runner, self._db, self._scan_id)
            subdomain_names = [h.subdomain for h in subdomains_hosts if h.subdomain]

            # Always include the apex domain itself as a seed. subfinder returns
            # only *subdomains*, and for many domains (no discoverable subdomains,
            # rate-limited, or single-host) it returns nothing — which would leave
            # dnsx (and the entire downstream pipeline) with an empty target list,
            # so every later tool "runs" but scans 0 targets. Seeding the apex
            # guarantees a domain scan always probes the domain the user typed.
            dnsx_targets = list(dict.fromkeys([self._target, *subdomain_names]))

            resolved_hosts = self._run_tool("dnsx", dnsx.run, dnsx_targets, runner, self._db, self._scan_id)
            ips = list({h.ip for h in resolved_hosts if h.ip})

        port_hosts = self._run_tool("naabu", naabu.run, ips, runner, self._db, self._scan_id)
        host_ports = [f"{h.ip}:{h.port}" for h in port_hosts if h.ip and h.port]

        http_hosts_list = self._run_tool("httpx", httpx.run, host_ports, runner, self._db, self._scan_id)
        http_urls = [h.url for h in http_hosts_list if h.url]

        self._run_tool("katana", katana.run, http_urls, runner, self._db, self._scan_id)

        all_targets = list({h.url or f"{h.ip}:{h.port}" for h in self._db.query_hosts_by_scan(self._scan_id) if h.url or (h.ip and h.port)})
        self._run_tool("nuclei", nuclei.run, all_targets, runner, self._db, self._scan_id)

        https_urls = [u for u in http_urls if u and u.startswith("https://")]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self._run_parallel_tool, "nmap",    nmap.run,    ips,         self._make_runner()),
                executor.submit(self._run_parallel_tool, "nikto",   nikto.run,   http_urls,   self._make_runner()),
                executor.submit(self._run_parallel_tool, "testssl", testssl.run, https_urls,  self._make_runner()),
            ]
            for future in futures:
                future.result()

        hosts_count = len(self._db.query_hosts_by_scan(self._scan_id))
        findings_count = len(self._db.query_findings_by_scan(self._scan_id))
        self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
        self.scan_complete.emit(hosts_count, findings_count)

    def _run_parallel_tool(self, name: str, fn, targets: list, runner: ToolRunner):
        self.tool_started.emit(name)
        self.log_line.emit(f"[{name}] starting...")
        try:
            results = fn(targets, runner, self._db, self._scan_id)
            self.tool_finished.emit(name, len(results))
            self.log_line.emit(f"[{name}] done — {len(results)} items")
            for item in results:
                self.finding_found.emit(item)
            return results
        except CancelledError:
            raise
        except Exception as exc:
            # Rule #2: isolate any failure in a parallel tool. This runs inside a
            # ThreadPool future; an uncaught exception here would re-raise at
            # future.result() and abort the whole scan.
            self.tool_failed.emit(name, str(exc))
            self.log_line.emit(f"[{name}] failed: {exc}")
            return []
