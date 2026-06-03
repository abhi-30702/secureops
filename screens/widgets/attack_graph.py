import math
import random
import numpy as np
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout
import pyqtgraph as pg

_NODE_COLORS = {
    "target":           "#00d4ff",
    "subdomain":        "#4488ff",
    "host":             "#00ff88",
    "url":              "#64748b",
    "finding_critical": "#ff4444",
    "finding_high":     "#ff8800",
    "finding_medium":   "#ffcc00",
    "finding_low":      "#4488ff",
    "finding_info":     "#64748b",
}

_NODE_SIZES = {
    "target":           20,
    "subdomain":        12,
    "host":             12,
    "url":              8,
    "finding_critical": 14,
    "finding_high":     12,
    "finding_medium":   10,
    "finding_low":      10,
    "finding_info":     8,
}


class AttackGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._positions: list[list[float]] = []
        self._node_types: list[str] = []
        self._node_keys: dict[str, int] = {}
        self._edges: list[tuple[int, int]] = []
        self._temperature = 100.0

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._step)

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        pg.setConfigOption("background", "#0a0e1a")
        pg.setConfigOption("foreground", "#64748b")
        self._view = pg.GraphicsLayoutWidget()
        self._plot = self._view.addPlot()
        self._plot.hideAxis("left")
        self._plot.hideAxis("bottom")
        self._plot.setAspectLocked(False)
        self._graph_item = pg.GraphItem()
        self._plot.addItem(self._graph_item)
        layout.addWidget(self._view)

    def reset(self, target: str = "Target"):
        self._timer.stop()
        self._positions = [[0.0, 0.0]]
        self._node_types = ["target"]
        self._node_keys = {"target": 0}
        self._edges = []
        self._temperature = 100.0
        self._redraw()

    def _add_node(self, key: str, node_type: str, parent_key: str | None = None) -> int:
        if key in self._node_keys:
            return self._node_keys[key]
        x = random.uniform(-30, 30)
        y = random.uniform(-30, 30)
        idx = len(self._positions)
        self._positions.append([x, y])
        self._node_types.append(node_type)
        self._node_keys[key] = idx
        parent_idx = self._node_keys.get(parent_key, 0)
        self._edges.append((parent_idx, idx))
        self._temperature = max(self._temperature, 20.0)
        return idx

    def add_host(self, host):
        if host.subdomain and not host.ip:
            self._add_node(f"sub_{host.subdomain}", "subdomain", "target")
        elif host.ip and host.port:
            parent = f"sub_{host.subdomain}" if host.subdomain else "target"
            self._add_node(f"host_{host.ip}_{host.port}", "host", parent)
        elif host.url:
            self._add_node(f"url_{host.url[:40]}", "url", "target")
        if not self._timer.isActive() and len(self._positions) > 1:
            self._timer.start(16)
        self._redraw()

    def add_finding(self, finding):
        node_type = f"finding_{finding.severity}"
        if node_type not in _NODE_COLORS:
            node_type = "finding_info"
        self._add_node(f"f_{finding.tool}_{finding.title[:30]}", node_type, "target")
        if not self._timer.isActive() and len(self._positions) > 1:
            self._timer.start(16)
        self._redraw()

    def on_scan_complete(self, hosts: int, findings: int):
        self._timer.stop()

    def _step(self):
        n = len(self._positions)
        if n < 2:
            return
        pos = np.array(self._positions, dtype=float)
        k = math.sqrt(160000.0 / n)
        disp = np.zeros_like(pos)

        for i in range(n):
            diff = pos[i] - pos
            dists = np.linalg.norm(diff, axis=1)
            dists[i] = 1.0
            forces = (k * k) / dists
            disp[i] += np.sum((diff / dists[:, np.newaxis]) * forces[:, np.newaxis], axis=0)

        for u, v in self._edges:
            delta = pos[u] - pos[v]
            dist = max(float(np.linalg.norm(delta)), 0.01)
            force = (dist * dist) / k
            direction = delta / dist
            disp[u] -= direction * force
            disp[v] += direction * force

        disp -= pos * 0.01

        norms = np.linalg.norm(disp, axis=1, keepdims=True)
        norms = np.maximum(norms, 0.001)
        scale = np.minimum(norms, self._temperature) / norms
        pos += disp * scale
        self._temperature = max(self._temperature * 0.98, 0.5)
        self._positions = pos.tolist()
        self._redraw()

    def _redraw(self):
        n = len(self._positions)
        if n == 0:
            return
        pos = np.array(self._positions, dtype=float)
        adj = np.array(self._edges, dtype=int) if self._edges else np.zeros((0, 2), dtype=int)
        brushes = [pg.mkBrush(_NODE_COLORS.get(t, "#64748b")) for t in self._node_types]
        sizes = [_NODE_SIZES.get(t, 10) for t in self._node_types]
        self._graph_item.setData(
            pos=pos,
            adj=adj,
            symbolBrush=brushes,
            size=sizes,
            pen=pg.mkPen("#1e2d40", width=1),
            symbol="o",
            pxMode=True,
        )

    @property
    def node_count(self) -> int:
        return len(self._positions)
