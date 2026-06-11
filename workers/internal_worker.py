import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding, Scan
from workers.base_tool import ToolRunner, ToolError, CancelledError


_ROUTER_PORTS      = {53, 23, 179}
_WORKSTATION_PORTS = {3389, 445}
_PRINTER_PORTS     = {515, 631, 9100}
_IOT_PORTS         = {1883, 8883, 102}
_SERVER_PORTS      = {80, 443, 22, 8080, 8443}


def _classify_device(ports: list[int]) -> str:
    port_set = set(ports)
    if port_set & _ROUTER_PORTS:
        return "router"
    if port_set & _WORKSTATION_PORTS:
        return "workstation"
    if port_set & _PRINTER_PORTS:
        return "printer"
    if port_set & _IOT_PORTS:
        return "iot"
    if port_set & _SERVER_PORTS:
        return "server"
    return "unknown"


class InternalWorker(QThread):
    finding_found = pyqtSignal(object)
    log_line      = pyqtSignal(str)
    scan_complete = pyqtSignal(int, int)
    scan_failed   = pyqtSignal(str)

    def __init__(self, subnets: list[str], scan_id: int, db: DB, parent=None):
        super().__init__(parent)
        self._subnets = subnets
        self._scan_id = scan_id
        self._db = db
        self._cancel_event = threading.Event()

    def stop(self):
        self._cancel_event.set()

    def run(self):
        runner = ToolRunner(self._cancel_event)
        try:
            live_ips = self._stage1_ping_sweep(runner)
        except CancelledError:
            self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
            return
        except Exception as exc:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit(f"Internal scan error: {exc}")
            return
        if live_ips is None:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            return
        if not live_ips:
            self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
            self.scan_complete.emit(0, 0)
            return

        try:
            findings_count = self._stage2_service_scan(runner, live_ips)
        except CancelledError:
            self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
            return

        self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
        self.scan_complete.emit(len(live_ips), findings_count)

    def _stage1_ping_sweep(self, runner: ToolRunner) -> list[str] | None:
        self.log_line.emit("[internal] Stage 1 — ping sweep")
        try:
            xml_out = runner.run_buffered(
                ["nmap", "-sn", "-T4", "-oX", "-"] + self._subnets,
                timeout=300,
            )
        except CancelledError:
            raise
        except ToolError as exc:
            self.scan_failed.emit(f"nmap not found or failed: {exc}")
            return None

        try:
            root = ET.fromstring(xml_out)
        except ET.ParseError:
            self.log_line.emit("[internal] ping sweep: failed to parse nmap XML")
            return []

        live = []
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr = host_el.find("address[@addrtype='ipv4']")
            if addr is not None:
                ip = addr.get("addr")
                if ip:
                    live.append(ip)
                    self.log_line.emit(f"[internal] live: {ip}")

        self.log_line.emit(f"[internal] Stage 1 complete — {len(live)} live hosts")
        return live

    def _stage2_service_scan(self, runner: ToolRunner, live_ips: list[str]) -> int:
        self.log_line.emit(f"[internal] Stage 2 — service scan ({len(live_ips)} hosts)")
        try:
            xml_out = runner.run_buffered(
                ["nmap", "-sV", "-T4", "--open", "-oX", "-"] + live_ips,
                timeout=600,
            )
        except CancelledError:
            raise
        except ToolError as exc:
            self.scan_failed.emit(f"nmap service scan failed: {exc}")
            return 0

        try:
            root = ET.fromstring(xml_out)
        except ET.ParseError:
            self.log_line.emit("[internal] service scan: failed to parse nmap XML")
            return 0

        count = 0
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "unknown")

            ports_el = host_el.find("ports")
            open_ports: list[int] = []
            port_desc_parts: list[str] = []
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portid = int(port_el.get("portid", 0))
                    open_ports.append(portid)
                    svc_el = port_el.find("service")
                    svc_name = svc_el.get("name", "") if svc_el is not None else ""
                    port_desc_parts.append(f"{portid}/{svc_name}" if svc_name else str(portid))

            device_type = _classify_device(open_ports)
            ports_str = ", ".join(port_desc_parts) or "none"

            finding = Finding(
                id=None,
                scan_id=self._scan_id,
                host_id=None,
                tool="nmap-internal",
                severity="info",
                title=f"{device_type} — {ip}",
                description=f"Open ports: {ports_str}",
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = self._db.insert_finding(finding)
            self.finding_found.emit(finding)
            self.log_line.emit(f"[internal] {ip} — {device_type} ({ports_str})")
            count += 1

        self.log_line.emit(f"[internal] Stage 2 complete — {count} hosts processed")
        return count
