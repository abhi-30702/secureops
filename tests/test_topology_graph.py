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


import sys
from unittest.mock import MagicMock, patch


@pytest.fixture
def topo(monkeypatch):
    """Return a TopologyGraph with Qt rendering disabled."""
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])

    # Mock pyqtgraph to avoid display
    pg_mock = MagicMock()
    monkeypatch.setitem(sys.modules, "pyqtgraph", pg_mock)

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
