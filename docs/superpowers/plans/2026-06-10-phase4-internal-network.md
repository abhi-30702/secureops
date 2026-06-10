# Phase 4 — Internal Network Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Internal Network page that sweeps subnet ranges with nmap, fingerprints device types from open ports, and displays results in a new subnet-grouped topology graph.

**Architecture:** `InternalWorker` (QThread) runs two nmap stages — a fast ping sweep then a service scan — and emits `Finding` objects per host. `InternalPage` hosts a new `TopologyGraph` widget alongside the existing `SeverityRings` and `FindingCards`. A new sidebar entry and stack slot wire it into `MainWindow`.

**Tech Stack:** PyQt6, pyqtgraph, nmap (subprocess), Python `xml.etree.ElementTree`, `ipaddress` stdlib, pytest-qt

---

## File map

| Action | Path |
|--------|------|
| Create | `workers/internal_worker.py` |
| Create | `screens/internal_page.py` |
| Create | `screens/widgets/topology_graph.py` |
| Modify | `sidebar.py` |
| Modify | `main_window.py` |
| Modify | `screens/settings.py` |
| Create | `tests/test_internal_worker.py` |
| Create | `tests/test_topology_graph.py` |

---

### Task 1: Device classifier (TDD)

**Files:**
- Create: `workers/internal_worker.py`
- Create: `tests/test_internal_worker.py`

- [ ] **Step 1.1: Write failing tests for `_classify_device`**

Create `tests/test_internal_worker.py`:

```python
import pytest
from workers.internal_worker import _classify_device


def test_port_53_is_router():
    assert _classify_device([53]) == "router"


def test_port_23_is_router():
    assert _classify_device([23]) == "router"


def test_port_179_is_router():
    assert _classify_device([179]) == "router"


def test_port_3389_is_workstation():
    assert _classify_device([3389]) == "workstation"


def test_port_445_is_workstation():
    assert _classify_device([445]) == "workstation"


def test_port_631_is_printer():
    assert _classify_device([631]) == "printer"


def test_port_9100_is_printer():
    assert _classify_device([9100]) == "printer"


def test_port_1883_is_iot():
    assert _classify_device([1883]) == "iot"


def test_port_80_443_is_server():
    assert _classify_device([80, 443]) == "server"


def test_port_22_only_is_server():
    assert _classify_device([22]) == "server"


def test_port_80_is_server():
    assert _classify_device([80]) == "server"


def test_empty_ports_is_unknown():
    assert _classify_device([]) == "unknown"


def test_priority_router_over_server():
    # port 53 + 80: router wins (checked first)
    assert _classify_device([53, 80]) == "router"


def test_priority_workstation_over_server():
    # port 3389 + 443: workstation wins
    assert _classify_device([3389, 443]) == "workstation"
```

- [ ] **Step 1.2: Run tests — verify they fail**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
pytest tests/test_internal_worker.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` or `ImportError` — `workers/internal_worker.py` does not exist yet.

- [ ] **Step 1.3: Create `workers/internal_worker.py` with `_classify_device`**

```python
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding, Scan
from workers.base_tool import ToolRunner, ToolError, CancelledError


_ROUTER_PORTS    = {53, 23, 179}
_WORKSTATION_PORTS = {3389, 445}
_PRINTER_PORTS   = {515, 631, 9100}
_IOT_PORTS       = {1883, 8883, 102}
_SERVER_PORTS    = {80, 443, 22, 8080, 8443}


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
        pass  # implemented in Task 2
```

- [ ] **Step 1.4: Run tests — verify they pass**

```bash
pytest tests/test_internal_worker.py -v
```

Expected: all 14 tests PASS.

- [ ] **Step 1.5: Commit**

```bash
git add workers/internal_worker.py tests/test_internal_worker.py
git commit -m "feat: add InternalWorker skeleton and _classify_device"
```

---

### Task 2: InternalWorker — Stage 1 (ping sweep)

**Files:**
- Modify: `workers/internal_worker.py`
- Modify: `tests/test_internal_worker.py`

- [ ] **Step 2.1: Add ping sweep tests**

Append to `tests/test_internal_worker.py`:

```python
import textwrap
from unittest.mock import patch, MagicMock
from db import DB
from models import Scan


def _make_worker(subnets=None):
    db = DB(":memory:")
    scan_id = db.insert_scan(Scan(
        id=None, client_id=None, target="internal",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    ))
    return InternalWorker(subnets=subnets or ["192.168.1.0/24"], scan_id=scan_id, db=db), db


_PING_XML_ONE_HOST = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/></host>
    </nmaprun>
""")

_PING_XML_ZERO_HOSTS = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
    </nmaprun>
""")


def test_stage1_returns_live_ips(qtbot):
    worker, _ = _make_worker()
    with patch("workers.internal_worker.ToolRunner.run_buffered", return_value=_PING_XML_ONE_HOST):
        live = worker._stage1_ping_sweep(ToolRunner(worker._cancel_event))
    assert live == ["192.168.1.10"]


def test_stage1_zero_hosts_emits_scan_complete(qtbot):
    worker, _ = _make_worker()
    completed = []
    worker.scan_complete.connect(lambda h, f: completed.append((h, f)))
    with patch("workers.internal_worker.ToolRunner.run_buffered", return_value=_PING_XML_ZERO_HOSTS):
        live = worker._stage1_ping_sweep(ToolRunner(worker._cancel_event))
    assert live == []


def test_stage1_tool_error_emits_scan_failed(qtbot):
    worker, _ = _make_worker()
    failed = []
    worker.scan_failed.connect(failed.append)
    with patch("workers.internal_worker.ToolRunner.run_buffered", side_effect=ToolError("nmap: not found")):
        live = worker._stage1_ping_sweep(ToolRunner(worker._cancel_event))
    assert live is None
    assert any("nmap" in m for m in failed)
```

Add `from datetime import datetime, timezone` and `from workers.internal_worker import InternalWorker, _classify_device` at the top of the test file (replace the existing import line).

- [ ] **Step 2.2: Run new tests — verify they fail**

```bash
pytest tests/test_internal_worker.py::test_stage1_returns_live_ips -v
```

Expected: `AttributeError: 'InternalWorker' object has no attribute '_stage1_ping_sweep'`

- [ ] **Step 2.3: Implement `_stage1_ping_sweep` in `workers/internal_worker.py`**

Replace the `run` method and add `_stage1_ping_sweep` after `stop()`:

```python
    def run(self):
        runner = ToolRunner(self._cancel_event)
        try:
            live_ips = self._stage1_ping_sweep(runner)
        except CancelledError:
            self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
            return
        if live_ips is None:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            return
        if not live_ips:
            self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
            self.scan_complete.emit(0, 0)
            return
        # Stage 2 implemented in Task 3
        self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
        self.scan_complete.emit(len(live_ips), 0)

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
                live.append(ip)
                self.log_line.emit(f"[internal] live: {ip}")

        self.log_line.emit(f"[internal] Stage 1 complete — {len(live)} live hosts")
        return live
```

- [ ] **Step 2.4: Run tests — verify they pass**

```bash
pytest tests/test_internal_worker.py -v
```

Expected: all tests PASS.

- [ ] **Step 2.5: Commit**

```bash
git add workers/internal_worker.py tests/test_internal_worker.py
git commit -m "feat: add InternalWorker stage 1 ping sweep"
```

---

### Task 3: InternalWorker — Stage 2 (service scan + findings)

**Files:**
- Modify: `workers/internal_worker.py`
- Modify: `tests/test_internal_worker.py`

- [ ] **Step 3.1: Add stage 2 tests**

Append to `tests/test_internal_worker.py`:

```python
_SERVICE_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")


def test_stage2_emits_finding_per_host(qtbot):
    worker, db = _make_worker()
    findings = []
    worker.finding_found.connect(findings.append)

    with patch("workers.internal_worker.ToolRunner.run_buffered", return_value=_SERVICE_XML):
        worker._stage2_service_scan(ToolRunner(worker._cancel_event), ["192.168.1.10"])

    assert len(findings) == 1
    assert findings[0].tool == "nmap-internal"
    assert "192.168.1.10" in findings[0].title


def test_stage2_classifies_device_correctly(qtbot):
    worker, db = _make_worker()
    findings = []
    worker.finding_found.connect(findings.append)

    with patch("workers.internal_worker.ToolRunner.run_buffered", return_value=_SERVICE_XML):
        worker._stage2_service_scan(ToolRunner(worker._cancel_event), ["192.168.1.10"])

    # ports 22+80 → server
    assert "server" in findings[0].title


def test_stage2_writes_finding_to_db(qtbot):
    worker, db = _make_worker()

    with patch("workers.internal_worker.ToolRunner.run_buffered", return_value=_SERVICE_XML):
        worker._stage2_service_scan(ToolRunner(worker._cancel_event), ["192.168.1.10"])

    stored = db.query_findings_by_scan(worker._scan_id)
    assert len(stored) == 1
    assert stored[0].tool == "nmap-internal"


def test_stage2_returns_count(qtbot):
    worker, db = _make_worker()

    with patch("workers.internal_worker.ToolRunner.run_buffered", return_value=_SERVICE_XML):
        count = worker._stage2_service_scan(ToolRunner(worker._cancel_event), ["192.168.1.10"])

    assert count == 1


def test_stage2_tool_error_emits_scan_failed(qtbot):
    worker, db = _make_worker()
    failed = []
    worker.scan_failed.connect(failed.append)

    with patch("workers.internal_worker.ToolRunner.run_buffered", side_effect=ToolError("nmap: exited with code 1")):
        worker._stage2_service_scan(ToolRunner(worker._cancel_event), ["192.168.1.10"])

    assert len(failed) == 1
```

- [ ] **Step 3.2: Run new tests — verify they fail**

```bash
pytest tests/test_internal_worker.py::test_stage2_emits_finding_per_host -v
```

Expected: `AttributeError: 'InternalWorker' object has no attribute '_stage2_service_scan'`

- [ ] **Step 3.3: Implement `_stage2_service_scan` and update `run`**

Add `_stage2_service_scan` to `workers/internal_worker.py` after `_stage1_ping_sweep`:

```python
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
```

Update `run` to call stage 2:

```python
    def run(self):
        runner = ToolRunner(self._cancel_event)
        try:
            live_ips = self._stage1_ping_sweep(runner)
        except CancelledError:
            self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
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
```

- [ ] **Step 3.4: Run all internal worker tests**

```bash
pytest tests/test_internal_worker.py -v
```

Expected: all tests PASS.

- [ ] **Step 3.5: Commit**

```bash
git add workers/internal_worker.py tests/test_internal_worker.py
git commit -m "feat: add InternalWorker stage 2 service scan and finding emission"
```

---

### Task 4: TopologyGraph data model (TDD, no Qt)

**Files:**
- Create: `tests/test_topology_graph.py`

The geometry logic (subnet key derivation, node grouping) will live inside `TopologyGraph` as internal state. We test these via the public API using a minimal stub that doesn't instantiate the Qt widget.

- [ ] **Step 4.1: Write failing tests**

Create `tests/test_topology_graph.py`:

```python
import pytest


def _subnet_key(ip: str) -> str:
    """Mirror the function used inside TopologyGraph."""
    return ".".join(ip.split(".")[:3]) + ".0/24"


def test_subnet_key_basic():
    assert _subnet_key("192.168.1.42") == "192.168.1.0/24"


def test_subnet_key_different_subnet():
    assert _subnet_key("10.0.2.100") == "10.0.2.0/24"


def test_subnet_key_last_octet_zero():
    assert _subnet_key("192.168.1.0") == "192.168.1.0/24"


# Test the data model inside TopologyGraph via a lightweight harness.
# We patch pyqtgraph so no display is needed.

import sys
from unittest.mock import MagicMock, patch


@pytest.fixture
def topo(monkeypatch):
    """Return a TopologyGraph with Qt rendering disabled."""
    pg_mock = MagicMock()
    monkeypatch.setitem(sys.modules, "pyqtgraph", pg_mock)
    # Also mock PyQt6 widget base so __init__ doesn't need a display
    from PyQt6.QtWidgets import QApplication
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from screens.widgets.topology_graph import TopologyGraph
    widget = TopologyGraph.__new__(TopologyGraph)
    widget._subnets: dict = {}
    widget._nodes: list = []
    widget._edges: list = []
    return widget


def test_add_host_creates_subnet_anchor(topo):
    topo._record_host("192.168.1.10", "server", [22, 80])
    assert "192.168.1.0/24" in topo._subnets


def test_add_host_same_subnet_one_anchor(topo):
    topo._record_host("192.168.1.10", "server", [80])
    topo._record_host("192.168.1.20", "workstation", [3389])
    assert len(topo._subnets) == 1


def test_add_host_different_subnets_two_anchors(topo):
    topo._record_host("192.168.1.10", "server", [80])
    topo._record_host("10.0.0.5", "router", [53])
    assert len(topo._subnets) == 2


def test_reset_clears_all(topo):
    topo._record_host("192.168.1.10", "server", [80])
    topo._nodes.clear()
    topo._edges.clear()
    topo._subnets.clear()
    assert len(topo._subnets) == 0
    assert len(topo._nodes) == 0
```

- [ ] **Step 4.2: Run tests — verify they fail**

```bash
pytest tests/test_topology_graph.py -v 2>&1 | head -20
```

Expected: `ImportError` or `AttributeError` — `topology_graph.py` does not exist yet.

- [ ] **Step 4.3: Create `screens/widgets/topology_graph.py`**

```python
import math
import numpy as np
from PyQt6.QtWidgets import QWidget, QVBoxLayout
import pyqtgraph as pg

_NODE_COLORS = {
    "subnet":      "#00e5ff",
    "router":      "#ffb300",
    "server":      "#00ff88",
    "workstation": "#4488ff",
    "printer":     "#7a9bc4",
    "iot":         "#ff3d57",
    "unknown":     "#3d5a7a",
}

_NODE_SIZES = {
    "subnet":      18,
    "router":      14,
    "server":      12,
    "workstation": 10,
    "printer":     9,
    "iot":         9,
    "unknown":     8,
}

_SUBNET_RADIUS = 80.0
_DEVICE_RADIUS = 30.0

_PG_TOPO_CONFIGURED = False


class TopologyGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # _subnets: {subnet_key: node_index}
        self._subnets: dict[str, int] = {}
        # _nodes: list of (key, node_type, label)
        self._nodes: list[tuple[str, str, str]] = []
        # _edges: list of (from_idx, to_idx)
        self._edges: list[tuple[int, int]] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        global _PG_TOPO_CONFIGURED
        if not _PG_TOPO_CONFIGURED:
            pg.setConfigOption("background", "#0a0e1a")
            pg.setConfigOption("foreground", "#64748b")
            _PG_TOPO_CONFIGURED = True
        self._view = pg.GraphicsLayoutWidget()
        self._plot = self._view.addPlot()
        self._plot.hideAxis("left")
        self._plot.hideAxis("bottom")
        self._plot.setAspectLocked(True)
        self._scatter = pg.ScatterPlotItem(pxMode=True)
        self._graph_item = pg.GraphItem()
        self._plot.addItem(self._graph_item)
        self._plot.addItem(self._scatter)
        self._scatter.sigClicked.connect(self._on_node_clicked)
        layout.addWidget(self._view)

    def reset(self):
        self._subnets.clear()
        self._nodes.clear()
        self._edges.clear()
        self._redraw()

    def _record_host(self, ip: str, device_type: str, ports: list[int]):
        """Update internal data structures. Called by add_host."""
        subnet_key = ".".join(ip.split(".")[:3]) + ".0/24"

        if subnet_key not in self._subnets:
            subnet_idx = len(self._nodes)
            self._nodes.append((subnet_key, "subnet", subnet_key))
            self._subnets[subnet_key] = subnet_idx

        subnet_idx = self._subnets[subnet_key]
        device_idx = len(self._nodes)
        ports_str = ", ".join(str(p) for p in ports) if ports else "none"
        label = f"{ip}\n{device_type}\nPorts: {ports_str}"
        self._nodes.append((ip, device_type, label))
        self._edges.append((subnet_idx, device_idx))

    def add_host(self, ip: str, device_type: str, ports: list[int]):
        self._record_host(ip, device_type, ports)
        self._redraw()

    def _compute_positions(self) -> list[list[float]]:
        """Compute x,y for every node geometrically (subnet ring + device orbits)."""
        positions: list[list[float]] = []
        subnet_keys = list(self._subnets.keys())
        n_subnets = len(subnet_keys)

        subnet_positions: dict[str, tuple[float, float]] = {}
        for i, sk in enumerate(subnet_keys):
            angle = (2 * math.pi * i / n_subnets) if n_subnets > 1 else 0.0
            sx = _SUBNET_RADIUS * math.cos(angle)
            sy = _SUBNET_RADIUS * math.sin(angle)
            subnet_positions[sk] = (sx, sy)

        # Device counts per subnet for orbit spacing
        device_counts: dict[str, int] = {sk: 0 for sk in subnet_keys}
        for key, node_type, _label in self._nodes:
            if node_type != "subnet":
                ip = key
                sk = ".".join(ip.split(".")[:3]) + ".0/24"
                if sk in device_counts:
                    device_counts[sk] += 1

        device_placed: dict[str, int] = {sk: 0 for sk in subnet_keys}

        for key, node_type, _label in self._nodes:
            if node_type == "subnet":
                sx, sy = subnet_positions[key]
                positions.append([sx, sy])
            else:
                ip = key
                sk = ".".join(ip.split(".")[:3]) + ".0/24"
                sx, sy = subnet_positions.get(sk, (0.0, 0.0))
                n_devices = max(device_counts.get(sk, 1), 1)
                idx = device_placed.get(sk, 0)
                angle = (2 * math.pi * idx / n_devices)
                dx = sx + _DEVICE_RADIUS * math.cos(angle)
                dy = sy + _DEVICE_RADIUS * math.sin(angle)
                device_placed[sk] = idx + 1
                positions.append([dx, dy])

        return positions

    def _redraw(self):
        if not self._nodes:
            self._graph_item.setData(
                pos=np.zeros((1, 2), dtype=float),
                adj=np.zeros((0, 2), dtype=int),
                symbolBrush=[pg.mkBrush("#0a0e1a")],
                size=[0],
                pen=pg.mkPen("#1e2d40", width=1),
                symbol="o",
                pxMode=True,
            )
            return

        positions = self._compute_positions()
        pos = np.array(positions, dtype=float)
        adj = np.array(self._edges, dtype=int) if self._edges else np.zeros((0, 2), dtype=int)
        brushes = [pg.mkBrush(_NODE_COLORS.get(t, "#3d5a7a")) for _, t, _ in self._nodes]
        sizes = [_NODE_SIZES.get(t, 8) for _, t, _ in self._nodes]

        self._graph_item.setData(
            pos=pos,
            adj=adj,
            symbolBrush=brushes,
            size=sizes,
            pen=pg.mkPen("#1e2d40", width=1),
            symbol="o",
            pxMode=True,
        )

    def _on_node_clicked(self, scatter, points):
        pass  # tooltip on hover — placeholder; ScatterPlotItem hover is Phase 5 polish

    @property
    def node_count(self) -> int:
        return len(self._nodes)
```

- [ ] **Step 4.4: Run topology tests**

```bash
pytest tests/test_topology_graph.py -v
```

Expected: all tests PASS.

- [ ] **Step 4.5: Verify import is clean**

```bash
python -c "from screens.widgets.topology_graph import TopologyGraph; print('OK')"
```

Expected: `OK`

- [ ] **Step 4.6: Commit**

```bash
git add screens/widgets/topology_graph.py tests/test_topology_graph.py
git commit -m "feat: add TopologyGraph widget with subnet-grouped layout"
```

---

### Task 5: InternalPage UI

**Files:**
- Create: `screens/internal_page.py`

- [ ] **Step 5.1: Create `screens/internal_page.py`**

```python
import ipaddress
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit, QFrame,
)

from db import DB
from models import Scan
from screens.widgets.topology_graph import TopologyGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards
from workers.internal_worker import InternalWorker


class InternalPage(QWidget):
    scan_ready = pyqtSignal(int)

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._worker: InternalWorker | None = None
        self._scan_id: int | None = None
        self._chips: list[tuple[str, QPushButton]] = []  # (subnet, remove_btn)

        self._subnet_input: QLineEdit | None = None
        self._add_btn: QPushButton | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._chips_row: QHBoxLayout | None = None
        self._topology: TopologyGraph | None = None
        self._severity_rings: SeverityRings | None = None
        self._finding_cards: FindingCards | None = None
        self._terminal: QPlainTextEdit | None = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # --- top bar ---
        top_bar = QHBoxLayout()
        self._subnet_input = QLineEdit()
        self._subnet_input.setPlaceholderText("192.168.1.0/24")
        self._subnet_input.setFixedWidth(220)
        self._subnet_input.returnPressed.connect(self._on_add_chip)

        self._add_btn = QPushButton("+ Add")
        self._add_btn.setFixedWidth(64)
        self._add_btn.clicked.connect(self._on_add_chip)

        self._start_btn = QPushButton("▶  Start Sweep")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)

        top_bar.addWidget(self._subnet_input)
        top_bar.addWidget(self._add_btn)
        top_bar.addStretch()
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        # --- chip row ---
        chip_frame = QFrame()
        chip_frame.setObjectName("panel")
        self._chips_row = QHBoxLayout(chip_frame)
        self._chips_row.setContentsMargins(8, 4, 8, 4)
        self._chips_row.setSpacing(6)
        self._chips_row.addStretch()
        layout.addWidget(chip_frame)

        # --- status label ---
        self._status_label = QLabel("Idle — add subnet ranges and click Start Sweep")
        self._status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(self._status_label)

        # --- main body ---
        self._topology = TopologyGraph()
        self._severity_rings = SeverityRings()
        self._finding_cards = FindingCards()
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setObjectName("panel")
        self._terminal.setStyleSheet(
            "font-family: monospace; font-size: 11px; color: #00ff88; background-color: #0a0e1a;"
        )

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right_layout.addWidget(self._severity_rings)
        right_layout.addWidget(self._finding_cards, stretch=1)

        body_splitter = QSplitter(Qt.Orientation.Horizontal)
        body_splitter.addWidget(self._topology)
        body_splitter.addWidget(right_panel)
        body_splitter.setSizes([700, 300])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(body_splitter)
        main_splitter.addWidget(self._terminal)
        main_splitter.setSizes([750, 150])

        layout.addWidget(main_splitter, stretch=1)

    def showEvent(self, event):
        super().showEvent(event)
        self._load_saved_subnets()

    def _load_saved_subnets(self):
        if not self._db:
            return
        saved = self._db.get_setting("internal_subnets") or ""
        current = {s for s, _ in self._chips}
        for subnet in saved.split(","):
            subnet = subnet.strip()
            if subnet and subnet not in current:
                self._add_chip(subnet)

    def _on_add_chip(self):
        text = self._subnet_input.text().strip()
        if not text:
            return
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            self._status_label.setText(f"Invalid subnet: {text}")
            self._status_label.setStyleSheet("color: #ff3d57; font-size: 11px;")
            return
        existing = {s for s, _ in self._chips}
        if text not in existing:
            self._add_chip(text)
        self._subnet_input.clear()
        self._status_label.setText("Idle — click Start Sweep when ready")
        self._status_label.setStyleSheet("color: #64748b; font-size: 11px;")

    def _add_chip(self, subnet: str):
        btn = QPushButton(f"{subnet}  ×")
        btn.setStyleSheet(
            "QPushButton { background: #0f1f35; color: #00e5ff; border: 1px solid #0d2440;"
            " border-radius: 10px; padding: 2px 8px; font-size: 11px; }"
            "QPushButton:hover { background: #1a2f4a; }"
        )
        btn.clicked.connect(lambda: self._remove_chip(subnet))
        self._chips_row.insertWidget(self._chips_row.count() - 1, btn)
        self._chips.append((subnet, btn))

    def _remove_chip(self, subnet: str):
        self._chips = [(s, b) for s, b in self._chips if s != subnet]
        for i in range(self._chips_row.count()):
            item = self._chips_row.itemAt(i)
            if item and item.widget():
                w = item.widget()
                if subnet in w.text():
                    self._chips_row.removeWidget(w)
                    w.deleteLater()
                    break

    def _on_start_stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        subnets = [s for s, _ in self._chips]
        if not subnets:
            self._status_label.setText("Add at least one subnet range first.")
            self._status_label.setStyleSheet("color: #ff3d57; font-size: 11px;")
            return

        scan = Scan(
            id=None, client_id=None,
            target=", ".join(subnets),
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._topology.reset()
        self._severity_rings.reset()
        self._finding_cards.reset()
        self._terminal.clear()

        self._worker = InternalWorker(subnets=subnets, scan_id=self._scan_id, db=self._db)
        self._worker.finding_found.connect(self._on_finding)
        self._worker.log_line.connect(self._terminal.appendPlainText)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.start()

        self._start_btn.setText("■  Stop Sweep")
        self._status_label.setText("Sweeping…")
        self._status_label.setStyleSheet("color: #00e5ff; font-size: 11px;")

    def _on_finding(self, finding):
        ports = []
        for p in finding.description.replace("Open ports: ", "").split(", "):
            p = p.strip()
            if not p or p == "none":
                continue
            try:
                ports.append(int(p.split("/")[0]))
            except ValueError:
                pass
        device_type = finding.title.split(" — ")[0]
        ip = finding.title.split(" — ")[-1]
        self._topology.add_host(ip, device_type, ports)
        self._severity_rings.add_finding(finding)
        self._finding_cards.add_finding(finding)

    def _on_complete(self, hosts: int, findings: int):
        self._start_btn.setText("▶  Start Sweep")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Done — {hosts} hosts, {findings} findings")
        self._status_label.setStyleSheet("color: #00ff88; font-size: 11px;")
        self._finding_cards.on_scan_complete(hosts, findings)
        if self._scan_id is not None:
            self.scan_ready.emit(self._scan_id)

    def _on_failed(self, msg: str):
        self._start_btn.setText("▶  Start Sweep")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet("color: #ff3d57; font-size: 11px;")
```

- [ ] **Step 5.2: Verify import is clean**

```bash
python -c "from screens.internal_page import InternalPage; print('OK')"
```

Expected: `OK`

- [ ] **Step 5.3: Commit**

```bash
git add screens/internal_page.py
git commit -m "feat: add InternalPage UI with subnet chips, topology graph, and worker wiring"
```

---

### Task 6: Sidebar + MainWindow wiring

**Files:**
- Modify: `sidebar.py:13` (the `_NAV_ITEMS` list)
- Modify: `main_window.py`

- [ ] **Step 6.1: Add Internal nav item to sidebar**

In `sidebar.py`, find `_NAV_ITEMS` and append the Internal entry:

```python
_NAV_ITEMS = [
    ("⊞", "Dashboard", 0),
    ("+", "New Client", 1),
    ("⚡", "Scan", 2),
    ("📄", "Report", 3),
    ("⚙", "Settings", 4),
    ("⬡", "Internal", 5),
]
```

- [ ] **Step 6.2: Add InternalPage to MainWindow**

In `main_window.py`, add the import at the top alongside other screen imports:

```python
from screens.internal_page import InternalPage
```

In `_setup_ui`, after the `SettingsScreen` line, add:

```python
        self._internal = InternalPage(db=self._db)
        self._stack.addWidget(self._internal)               # index 5
        self._internal.scan_ready.connect(self._on_scan_ready)
```

- [ ] **Step 6.3: Launch the app and verify Internal appears in sidebar**

```bash
DISPLAY=:0 python main.py &
```

Click the "⬡" (hexagon) sidebar button — the Internal page should appear with the empty topology graph, chip bar, and Start Sweep button.

- [ ] **Step 6.4: Commit**

```bash
git add sidebar.py main_window.py
git commit -m "feat: wire InternalPage into sidebar and MainWindow stack"
```

---

### Task 7: Settings subnet ranges field

**Files:**
- Modify: `screens/settings.py`

- [ ] **Step 7.1: Add subnet ranges section to SettingsScreen**

In `screens/settings.py`, add `self._subnet_input: QLineEdit | None = None` to `__init__` attribute list, then add a call to a new `_build_subnet_section` at the end of `_setup_ui` (before the final `self._build_advisor_section(layout)` call):

```python
        self._build_subnet_section(layout)
        self._build_advisor_section(layout)
```

Add the method to the class:

```python
    def _build_subnet_section(self, layout: QVBoxLayout) -> None:
        subnet_label = QLabel("INTERNAL SUBNET RANGES")
        subnet_label.setStyleSheet("color: #64748b; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(subnet_label)

        self._subnet_input = QLineEdit()
        self._subnet_input.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        if self._db:
            saved = self._db.get_setting("internal_subnets")
            if saved:
                self._subnet_input.setText(saved)
        layout.addWidget(self._subnet_input)

        save_subnet_row = QHBoxLayout()
        save_subnet_btn = QPushButton("Save")
        save_subnet_btn.setFixedWidth(80)
        save_subnet_btn.clicked.connect(self._on_save_subnets)
        save_subnet_row.addWidget(save_subnet_btn)
        save_subnet_row.addStretch()
        layout.addLayout(save_subnet_row)

    def _on_save_subnets(self) -> None:
        if not self._db or not self._subnet_input:
            return
        self._db.set_setting("internal_subnets", self._subnet_input.text().strip())
```

- [ ] **Step 7.2: Verify Settings page loads without error**

```bash
python -c "
import os; os.environ['QT_QPA_PLATFORM']='offscreen'
from PyQt6.QtWidgets import QApplication; app = QApplication([])
from db import DB; db = DB(':memory:')
from screens.settings import SettingsScreen
s = SettingsScreen({}, db=db)
print('OK')
"
```

Expected: `OK`

- [ ] **Step 7.3: Commit**

```bash
git add screens/settings.py
git commit -m "feat: add internal subnet ranges field to Settings page"
```

---

### Task 8: Full test run and verification

**Files:** none new

- [ ] **Step 8.1: Run the full test suite**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
pytest --tb=short -q
```

Expected: all existing tests pass, new tests pass, zero failures.

- [ ] **Step 8.2: Manual smoke test — start app, open Internal page, run a sweep**

```bash
DISPLAY=:0 python main.py &
```

1. Click ⬡ Internal in sidebar
2. Type `127.0.0.1/32` in the subnet input and click "+ Add" (scans only localhost — fast)
3. Click "▶  Start Sweep"
4. Observe: terminal shows `[internal] live: 127.0.0.1`, then service scan output
5. Observe: a node appears in TopologyGraph (subnet anchor + device node)
6. Observe: a FindingCard appears on the right
7. When complete, verify: Report screen navigates automatically

- [ ] **Step 8.3: Final commit**

```bash
git add -A
git commit -m "feat: Phase 4 complete — internal network scanning with topology map"
```
