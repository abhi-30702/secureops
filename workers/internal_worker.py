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
        pass  # stage 1 and 2 added in later tasks
