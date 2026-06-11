import textwrap
from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest

from workers.internal_worker import InternalWorker, _classify_device
from workers.base_tool import ToolRunner, ToolError
from db import DB
from models import Scan


# ── classifier tests (existing) ──────────────────────────────────────────────

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
    assert _classify_device([53, 80]) == "router"

def test_priority_workstation_over_server():
    assert _classify_device([3389, 443]) == "workstation"


# ── helpers ───────────────────────────────────────────────────────────────────

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


# ── stage 1 tests ─────────────────────────────────────────────────────────────

def test_stage1_returns_live_ips(qtbot):
    worker, _ = _make_worker()
    mock_runner = MagicMock()
    mock_runner.run_buffered.return_value = _PING_XML_ONE_HOST
    live = worker._stage1_ping_sweep(mock_runner)
    assert live == ["192.168.1.10"]


def test_stage1_zero_hosts_returns_empty_list(qtbot):
    worker, _ = _make_worker()
    mock_runner = MagicMock()
    mock_runner.run_buffered.return_value = _PING_XML_ZERO_HOSTS
    live = worker._stage1_ping_sweep(mock_runner)
    assert live == []


def test_stage1_tool_error_emits_scan_failed(qtbot):
    worker, _ = _make_worker()
    failed = []
    worker.scan_failed.connect(failed.append)
    mock_runner = MagicMock()
    mock_runner.run_buffered.side_effect = ToolError("nmap: not found")
    live = worker._stage1_ping_sweep(mock_runner)
    assert live is None
    assert any("nmap" in m for m in failed)
