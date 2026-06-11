import math
import numpy as np
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout
import pyqtgraph as pg

_NODE_COLORS = {
    "subnet":      "#5F4A8B",
    "router":      "#B38B00",
    "server":      "#00A85A",
    "workstation": "#8B75C2",
    "printer":     "#7a9bc4",
    "iot":         "#C94A62",
    "unknown":     "#5A7A9B",
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
        self._redraw_timer = QTimer(self)
        self._redraw_timer.setSingleShot(True)
        self._redraw_timer.setInterval(100)
        self._redraw_timer.timeout.connect(self._redraw)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        global _PG_TOPO_CONFIGURED
        if not _PG_TOPO_CONFIGURED:
            pg.setConfigOption("background", "#FEFACD")
            pg.setConfigOption("foreground", "#2A1F45")
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
        if hasattr(self, "_graph_item"):
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
        self._redraw_timer.start()

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
                symbolBrush=[pg.mkBrush("#FEFACD")],
                size=[0],
                pen=pg.mkPen("#8B75C2", width=1),
                symbol="o",
                pxMode=True,
            )
            return

        positions = self._compute_positions()
        pos = np.array(positions, dtype=float)
        adj = np.array(self._edges, dtype=int) if self._edges else np.zeros((0, 2), dtype=int)
        brushes = [pg.mkBrush(_NODE_COLORS.get(t, "#5A7A9B")) for _, t, _ in self._nodes]
        sizes = [_NODE_SIZES.get(t, 8) for _, t, _ in self._nodes]

        self._graph_item.setData(
            pos=pos,
            adj=adj,
            symbolBrush=brushes,
            size=sizes,
            pen=pg.mkPen("#8B75C2", width=1),
            symbol="o",
            pxMode=True,
        )

    def _on_node_clicked(self, scatter, points):
        pass

    @property
    def node_count(self) -> int:
        return len(self._nodes)
