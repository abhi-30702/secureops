# Phase 3 — Live Visuals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 4 placeholder panels in `ScanViewScreen` with live visual widgets — a pipeline tracker, force-directed attack graph, severity ring charts, and a streaming finding card list — all driven by existing `ScanWorker` signals.

**Architecture:** Each visual is an isolated `QWidget` subclass in `screens/widgets/` with a clean public slot interface (`reset()`, `add_host()`, `add_finding()`, `on_tool_started()`, etc.). `ScanViewScreen` instantiates them and wires ScanWorker signals to their slots. No widget knows about ScanWorker or the DB.

**Tech Stack:** PyQt6, pyqtgraph 0.14 (AttackGraph), QPainter (SeverityRings), QPropertyAnimation + QGraphicsOpacityEffect (animations), numpy (force simulation)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `screens/widgets/__init__.py` | Create | Empty package marker |
| `screens/widgets/pipeline_tracker.py` | Create | 9-node pipeline tracker, state machine per node |
| `screens/widgets/severity_rings.py` | Create | 4 QPainter donut charts with animated fill |
| `screens/widgets/finding_cards.py` | Create | Slide-in finding card stream |
| `screens/widgets/attack_graph.py` | Create | Force-directed graph, pyqtgraph + numpy FR layout |
| `screens/scan_view.py` | Modify | Replace 4 QFrame placeholders with widget instances, wire signals |
| `tests/test_widget_pipeline_tracker.py` | Create | State transitions, count label, reset |
| `tests/test_widget_severity_rings.py` | Create | Per-severity increment, count accuracy, reset |
| `tests/test_widget_finding_cards.py` | Create | Card added, newest at top, cap at 200, summary card |
| `tests/test_widget_attack_graph.py` | Create | Node count, timer lifecycle, reset |
| `tests/test_screen_scan_view.py` | Modify | 4 new assertions confirming widget types |

---

## Task 1: Package structure + PipelineTracker

**Files:**
- Create: `screens/widgets/__init__.py`
- Create: `screens/widgets/pipeline_tracker.py`
- Create: `tests/test_widget_pipeline_tracker.py`

- [ ] **Step 1: Create `screens/widgets/__init__.py`**

Empty file.

- [ ] **Step 2: Write failing tests**

`tests/test_widget_pipeline_tracker.py`:
```python
import pytest
from screens.widgets.pipeline_tracker import PipelineTracker


def test_pipeline_tracker_all_nodes_start_idle(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    for name, node in tracker._nodes.items():
        assert node.state == "idle"


def test_pipeline_tracker_on_tool_started_sets_running(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("subfinder")
    assert tracker._nodes["subfinder"].state == "running"


def test_pipeline_tracker_on_tool_finished_sets_done(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("subfinder")
    tracker.on_tool_finished("subfinder", 14)
    assert tracker._nodes["subfinder"].state == "done"
    assert tracker._nodes["subfinder"]._count_label.text() == "14"


def test_pipeline_tracker_on_tool_failed_sets_failed(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("nmap")
    tracker.on_tool_failed("nmap", "not found")
    assert tracker._nodes["nmap"].state == "failed"


def test_pipeline_tracker_reset_returns_all_to_idle(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("nuclei")
    tracker.on_tool_finished("nuclei", 3)
    tracker.reset()
    assert tracker._nodes["nuclei"].state == "idle"


def test_pipeline_tracker_has_all_nine_nodes(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    expected = {"subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei", "nmap", "nikto", "testssl"}
    assert set(tracker._nodes.keys()) == expected
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_widget_pipeline_tracker.py -v
```
Expected: `ModuleNotFoundError: No module named 'screens.widgets'`

- [ ] **Step 4: Write `screens/widgets/pipeline_tracker.py`**

```python
from PyQt6.QtCore import Qt, QPropertyAnimation
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGraphicsOpacityEffect,
)

_MAIN_CHAIN = ["subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei"]
_PARALLEL = ["nmap", "nikto", "testssl"]

_DOT_COLORS = {
    "idle":    "#2d4a6b",
    "running": "#00d4ff",
    "done":    "#00ff88",
    "failed":  "#ff4444",
}


class _ToolNode(QFrame):
    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self.name = name
        self._state = "idle"
        self._animation: QPropertyAnimation | None = None
        self.setObjectName("panel")
        self.setFixedSize(88, 58)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._dot = QLabel("●")
        self._dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['idle']}; font-size: 10px;")

        self._name_label = QLabel(name)
        self._name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._name_label.setStyleSheet("color: #e2e8f0; font-size: 9px; font-family: monospace;")

        self._count_label = QLabel("")
        self._count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._count_label.setStyleSheet("color: #64748b; font-size: 9px;")
        self._count_label.setVisible(False)

        layout.addWidget(self._dot)
        layout.addWidget(self._name_label)
        layout.addWidget(self._count_label)

    def set_running(self):
        self._state = "running"
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['running']}; font-size: 10px;")
        effect = QGraphicsOpacityEffect(self._dot)
        self._dot.setGraphicsEffect(effect)
        self._animation = QPropertyAnimation(effect, b"opacity")
        self._animation.setDuration(600)
        self._animation.setKeyValueAt(0.0, 1.0)
        self._animation.setKeyValueAt(0.5, 0.3)
        self._animation.setKeyValueAt(1.0, 1.0)
        self._animation.setLoopCount(-1)
        self._animation.start()

    def set_done(self, count: int):
        self._state = "done"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['done']}; font-size: 10px;")
        self._count_label.setText(str(count))
        self._count_label.setVisible(True)

    def set_failed(self):
        self._state = "failed"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['failed']}; font-size: 10px;")
        self._count_label.setText("failed")
        self._count_label.setVisible(True)

    def reset(self):
        self._state = "idle"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['idle']}; font-size: 10px;")
        self._count_label.setText("")
        self._count_label.setVisible(False)

    def _stop_anim(self):
        if self._animation:
            self._animation.stop()
            self._animation = None
        self._dot.setGraphicsEffect(None)

    @property
    def state(self) -> str:
        return self._state


class PipelineTracker(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: dict[str, _ToolNode] = {}
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(8)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        main_row = QHBoxLayout()
        main_row.setSpacing(2)
        main_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for name in _MAIN_CHAIN:
            node = _ToolNode(name)
            self._nodes[name] = node
            main_row.addWidget(node)
            if name != _MAIN_CHAIN[-1]:
                arr = QLabel("→")
                arr.setStyleSheet("color: #2d4a6b; font-size: 12px;")
                main_row.addWidget(arr)

        parallel_row = QHBoxLayout()
        parallel_row.setSpacing(8)
        parallel_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for name in _PARALLEL:
            node = _ToolNode(name)
            self._nodes[name] = node
            parallel_row.addWidget(node)

        outer.addLayout(main_row)
        outer.addLayout(parallel_row)

    def on_tool_started(self, name: str):
        if name in self._nodes:
            self._nodes[name].set_running()

    def on_tool_finished(self, name: str, count: int):
        if name in self._nodes:
            self._nodes[name].set_done(count)

    def on_tool_failed(self, name: str, msg: str):
        if name in self._nodes:
            self._nodes[name].set_failed()

    def on_scan_complete(self, hosts: int, findings: int):
        pass

    def reset(self):
        for node in self._nodes.values():
            node.reset()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_widget_pipeline_tracker.py -v
```
Expected: all 6 tests PASS.

- [ ] **Step 6: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/widgets/__init__.py screens/widgets/pipeline_tracker.py tests/test_widget_pipeline_tracker.py
git commit -m "feat: PipelineTracker — 9-node pipeline status widget

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: SeverityRings

**Files:**
- Create: `screens/widgets/severity_rings.py`
- Create: `tests/test_widget_severity_rings.py`

- [ ] **Step 1: Write failing tests**

`tests/test_widget_severity_rings.py`:
```python
from models import Finding
from screens.widgets.severity_rings import SeverityRings


def _finding(severity: str) -> Finding:
    return Finding(id=None, scan_id=1, host_id=None, tool="nuclei",
                   severity=severity, title="Test", description="",
                   raw_json="{}", created_at="2024-01-01T00:00:00")


def test_severity_rings_has_four_rings(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    assert len(rings._rings) == 4


def test_severity_rings_counts_start_at_zero(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    for ring in rings._rings.values():
        assert ring.count == 0


def test_severity_rings_critical_increments_on_finding(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("critical"))
    assert rings._rings["critical"].count == 1


def test_severity_rings_high_increments_on_finding(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("high"))
    assert rings._rings["high"].count == 1
    assert rings._rings["critical"].count == 0


def test_severity_rings_reset_zeroes_all_counts(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("critical"))
    rings.add_finding(_finding("medium"))
    rings.reset()
    for ring in rings._rings.values():
        assert ring.count == 0


def test_severity_rings_ignores_unknown_severity(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("info"))
    total = sum(r.count for r in rings._rings.values())
    assert total == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_widget_severity_rings.py -v
```
Expected: `ModuleNotFoundError: No module named 'screens.widgets.severity_rings'`

- [ ] **Step 3: Write `screens/widgets/severity_rings.py`**

```python
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect
from PyQt6.QtWidgets import QWidget, QHBoxLayout
from PyQt6.QtGui import QPainter, QPen, QColor, QFont

_SEVERITIES = ["critical", "high", "medium", "low"]
_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#4488ff",
}


class _RingWidget(QWidget):
    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self._severity = severity
        self._color = _COLORS[severity]
        self._count = 0
        self._fill = 0.0
        self._animation: QPropertyAnimation | None = None
        self.setFixedSize(110, 130)

    def _get_fill(self) -> float:
        return self._fill

    def _set_fill(self, value: float):
        self._fill = value
        self.update()

    from PyQt6.QtCore import pyqtProperty
    fill = pyqtProperty(float, _get_fill, _set_fill)

    def increment(self):
        self._count += 1
        new_fill = self._count / max(self._count, 10)
        if self._animation:
            self._animation.stop()
        self._animation = QPropertyAnimation(self, b"fill")
        self._animation.setDuration(300)
        self._animation.setStartValue(self._fill)
        self._animation.setEndValue(new_fill)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.start()

    def reset(self):
        if self._animation:
            self._animation.stop()
            self._animation = None
        self._count = 0
        self._fill = 0.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRect(15, 10, 80, 80)

        bg_pen = QPen(QColor("#1e2d40"))
        bg_pen.setWidth(12)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        if self._fill > 0:
            fg_pen = QPen(QColor(self._color))
            fg_pen.setWidth(12)
            fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(fg_pen)
            start = 90 * 16
            span = -int(self._fill * 360 * 16)
            painter.drawArc(rect, start, span)

        painter.setPen(QColor("#e2e8f0"))
        f = QFont()
        f.setBold(True)
        f.setPointSize(16)
        painter.setFont(f)
        painter.drawText(QRect(0, 10, 110, 80), Qt.AlignmentFlag.AlignCenter, str(self._count))

        painter.setPen(QColor("#64748b"))
        f2 = QFont()
        f2.setPointSize(8)
        painter.setFont(f2)
        painter.drawText(QRect(0, 95, 110, 20), Qt.AlignmentFlag.AlignCenter, self._severity.upper())

    @property
    def count(self) -> int:
        return self._count


class SeverityRings(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rings: dict[str, _RingWidget] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)
        for sev in _SEVERITIES:
            ring = _RingWidget(sev)
            self._rings[sev] = ring
            layout.addWidget(ring)

    def add_finding(self, finding):
        if finding.severity in self._rings:
            self._rings[finding.severity].increment()

    def on_scan_complete(self, hosts: int, findings: int):
        pass

    def reset(self):
        for ring in self._rings.values():
            ring.reset()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_widget_severity_rings.py -v
```
Expected: all 6 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/widgets/severity_rings.py tests/test_widget_severity_rings.py
git commit -m "feat: SeverityRings — animated QPainter donut charts

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: FindingCards

**Files:**
- Create: `screens/widgets/finding_cards.py`
- Create: `tests/test_widget_finding_cards.py`

- [ ] **Step 1: Write failing tests**

`tests/test_widget_finding_cards.py`:
```python
from models import Finding
from screens.widgets.finding_cards import FindingCards


def _finding(tool: str = "nuclei", severity: str = "critical",
             title: str = "Test Finding", description: str = "desc") -> Finding:
    return Finding(id=None, scan_id=1, host_id=None, tool=tool,
                   severity=severity, title=title, description=description,
                   raw_json="{}", created_at="2024-01-01T00:00:00")


def test_finding_cards_starts_empty(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    assert fc.card_count == 0


def test_finding_cards_add_finding_increments_count(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.add_finding(_finding())
    assert fc.card_count == 1


def test_finding_cards_newest_at_top(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.add_finding(_finding(title="First"))
    fc.add_finding(_finding(title="Second"))
    assert fc._cards[0].title == "Second"
    assert fc._cards[1].title == "First"


def test_finding_cards_capped_at_200(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    for i in range(205):
        fc.add_finding(_finding(title=f"Finding {i}"))
    assert fc.card_count == 200


def test_finding_cards_scan_complete_adds_summary(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.on_scan_complete(47, 12)
    assert fc.card_count == 1
    assert fc._cards[0].title == "Scan complete"


def test_finding_cards_reset_clears_all(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.add_finding(_finding())
    fc.add_finding(_finding())
    fc.reset()
    assert fc.card_count == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_widget_finding_cards.py -v
```
Expected: `ModuleNotFoundError: No module named 'screens.widgets.finding_cards'`

- [ ] **Step 3: Write `screens/widgets/finding_cards.py`**

```python
from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QFrame, QLabel, QGraphicsOpacityEffect,
)

_MAX_CARDS = 200

_SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#4488ff",
    "info":     "#64748b",
}


class _Card(QFrame):
    def __init__(self, title: str, tool: str, severity: str,
                 description: str, border_color: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setFixedHeight(70)
        self.setStyleSheet(
            f"QFrame {{ border-left: 3px solid {border_color};"
            f" background-color: #111827; border-radius: 4px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(2)

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        top = QLabel(f"{tool}  ·  {ts}")
        top.setStyleSheet("color: #64748b; font-size: 10px;")

        title_label = QLabel(title)
        title_label.setStyleSheet(
            f"color: #e2e8f0; font-size: 13px; font-weight: bold;"
        )

        desc_label = QLabel((description or "")[:100])
        desc_label.setStyleSheet("color: #64748b; font-size: 11px;")
        desc_label.setWordWrap(True)

        layout.addWidget(top)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)


class FindingCards(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: list[_Card] = []
        self._container = QWidget()
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._layout.addStretch()
        self.setWidget(self._container)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

    def add_finding(self, finding):
        self._trim_if_needed()
        color = _SEVERITY_COLORS.get(finding.severity, "#64748b")
        card = _Card(
            title=finding.title,
            tool=finding.tool,
            severity=finding.severity,
            description=finding.description,
            border_color=color,
        )
        card.setMaximumHeight(0)
        self._layout.insertWidget(0, card)
        self._cards.insert(0, card)

        effect = QGraphicsOpacityEffect(card)
        card.setGraphicsEffect(effect)
        effect.setOpacity(0.0)

        anim_h = QPropertyAnimation(card, b"maximumHeight")
        anim_h.setDuration(250)
        anim_h.setStartValue(0)
        anim_h.setEndValue(70)
        anim_h.setEasingCurve(QEasingCurve.Type.OutCubic)

        anim_o = QPropertyAnimation(effect, b"opacity")
        anim_o.setDuration(250)
        anim_o.setStartValue(0.0)
        anim_o.setEndValue(1.0)

        anim_h.start()
        anim_o.start()
        card._anim_h = anim_h
        card._anim_o = anim_o

        self.verticalScrollBar().setValue(0)

    def on_scan_complete(self, hosts: int, findings: int):
        card = _Card(
            title="Scan complete",
            tool="scan",
            severity="info",
            description=f"{hosts} hosts discovered, {findings} findings",
            border_color="#00d4ff",
        )
        card.setMaximumHeight(70)
        self._layout.insertWidget(0, card)
        self._cards.insert(0, card)
        self.verticalScrollBar().setValue(0)

    def reset(self):
        for card in self._cards:
            self._layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

    def _trim_if_needed(self):
        if len(self._cards) >= _MAX_CARDS:
            oldest = self._cards.pop()
            self._layout.removeWidget(oldest)
            oldest.deleteLater()

    @property
    def card_count(self) -> int:
        return len(self._cards)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_widget_finding_cards.py -v
```
Expected: all 6 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/widgets/finding_cards.py tests/test_widget_finding_cards.py
git commit -m "feat: FindingCards — slide-in finding card stream

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 4: AttackGraph

**Files:**
- Create: `screens/widgets/attack_graph.py`
- Create: `tests/test_widget_attack_graph.py`

- [ ] **Step 1: Write failing tests**

`tests/test_widget_attack_graph.py`:
```python
from models import Host, Finding
from screens.widgets.attack_graph import AttackGraph


def _host(subdomain: str = None, ip: str = None, port: int = None,
          url: str = None) -> Host:
    return Host(id=None, scan_id=1, subdomain=subdomain, ip=ip, port=port,
                protocol="tcp", service=None, url=url,
                source_tool="subfinder", created_at="2024-01-01T00:00:00")


def _finding(severity: str = "critical") -> Finding:
    return Finding(id=None, scan_id=1, host_id=None, tool="nuclei",
                   severity=severity, title="Test Vuln", description="",
                   raw_json="{}", created_at="2024-01-01T00:00:00")


def test_attack_graph_starts_with_one_node_after_reset(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    assert graph.node_count == 1


def test_attack_graph_add_host_increases_node_count(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    assert graph.node_count == 2


def test_attack_graph_add_finding_increases_node_count(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_finding(_finding())
    assert graph.node_count == 2


def test_attack_graph_duplicate_host_not_added_twice(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    graph.add_host(_host(subdomain="api.example.com"))
    assert graph.node_count == 2


def test_attack_graph_timer_stops_on_scan_complete(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    graph.on_scan_complete(5, 3)
    assert not graph._timer.isActive()


def test_attack_graph_reset_clears_nodes(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    graph.add_finding(_finding())
    graph.reset()
    assert graph.node_count == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_widget_attack_graph.py -v
```
Expected: `ModuleNotFoundError: No module named 'screens.widgets.attack_graph'`

- [ ] **Step 3: Write `screens/widgets/attack_graph.py`**

```python
import math
import random
import numpy as np
from PyQt6.QtCore import Qt, QTimer
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

        self._timer = QTimer()
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_widget_attack_graph.py -v
```
Expected: all 6 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/widgets/attack_graph.py tests/test_widget_attack_graph.py
git commit -m "feat: AttackGraph — force-directed graph with FR layout

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 5: ScanViewScreen integration

**Files:**
- Modify: `screens/scan_view.py`
- Modify: `tests/test_screen_scan_view.py` (append 4 new tests)

- [ ] **Step 1: Append failing tests to `tests/test_screen_scan_view.py`**

Read the current file, then append to the bottom:
```python
from screens.widgets.pipeline_tracker import PipelineTracker
from screens.widgets.attack_graph import AttackGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards


def test_scan_view_pipeline_panel_is_pipeline_tracker(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._pipeline_panel, PipelineTracker)


def test_scan_view_attack_graph_panel_is_attack_graph(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._attack_graph_panel, AttackGraph)


def test_scan_view_severity_panel_is_severity_rings(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._severity_panel, SeverityRings)


def test_scan_view_finding_cards_panel_is_finding_cards(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._finding_cards_panel, FindingCards)
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py::test_scan_view_pipeline_panel_is_pipeline_tracker -v
```
Expected: FAIL — `assert isinstance(QFrame, PipelineTracker)` fails.

- [ ] **Step 3: Rewrite `screens/scan_view.py`**

```python
from datetime import datetime, timezone
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QSplitter, QPlainTextEdit,
)
from screens.widgets.pipeline_tracker import PipelineTracker
from screens.widgets.attack_graph import AttackGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards


class ScanViewScreen(QWidget):
    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._target_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._pipeline_panel: PipelineTracker | None = None
        self._attack_graph_panel: AttackGraph | None = None
        self._severity_panel: SeverityRings | None = None
        self._finding_cards_panel: FindingCards | None = None
        self._terminal_panel: QPlainTextEdit | None = None
        self._worker = None
        self._scan_id: int | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top_bar = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.setToolTip("Enter a target and click to scan" if self._db else "DB not initialised")
        self._start_btn.clicked.connect(self._on_start_cancel)
        top_bar.addWidget(self._target_input, stretch=1)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(self._status_label)

        self._pipeline_panel = PipelineTracker()
        self._attack_graph_panel = AttackGraph()
        self._attack_graph_panel.reset()
        self._severity_panel = SeverityRings()
        self._finding_cards_panel = FindingCards()

        self._terminal_panel = QPlainTextEdit()
        self._terminal_panel.setReadOnly(True)
        self._terminal_panel.setObjectName("panel")
        self._terminal_panel.setStyleSheet(
            "font-family: monospace; font-size: 11px; color: #00ff88; background-color: #0a0e1a;"
        )

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._pipeline_panel)
        top_splitter.addWidget(self._attack_graph_panel)
        top_splitter.setSizes([250, 750])

        mid_splitter = QSplitter(Qt.Orientation.Horizontal)
        mid_splitter.addWidget(self._severity_panel)
        mid_splitter.addWidget(self._finding_cards_panel)
        mid_splitter.setSizes([250, 750])

        top_mid = QWidget()
        top_mid_layout = QVBoxLayout(top_mid)
        top_mid_layout.setContentsMargins(0, 0, 0, 0)
        top_mid_layout.setSpacing(8)
        top_mid_layout.addWidget(top_splitter, stretch=1)
        top_mid_layout.addWidget(mid_splitter, stretch=1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_mid)
        main_splitter.addWidget(self._terminal_panel)
        main_splitter.setSizes([800, 200])

        layout.addWidget(main_splitter, stretch=1)

    def _on_start_cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            return

        target = self._target_input.text().strip()
        if not target:
            self._status_label.setText("Enter a target first.")
            return

        from models import Scan
        from workers.scan_worker import ScanWorker

        scan = Scan(
            id=None,
            client_id=None,
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._pipeline_panel.reset()
        self._attack_graph_panel.reset(target)
        self._severity_panel.reset()
        self._finding_cards_panel.reset()

        self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)

        self._worker.tool_started.connect(self._pipeline_panel.on_tool_started)
        self._worker.tool_finished.connect(self._pipeline_panel.on_tool_finished)
        self._worker.tool_failed.connect(self._pipeline_panel.on_tool_failed)
        self._worker.scan_complete.connect(self._pipeline_panel.on_scan_complete)

        self._worker.host_found.connect(self._attack_graph_panel.add_host)
        self._worker.finding_found.connect(self._attack_graph_panel.add_finding)
        self._worker.scan_complete.connect(self._attack_graph_panel.on_scan_complete)

        self._worker.finding_found.connect(self._severity_panel.add_finding)
        self._worker.scan_complete.connect(self._severity_panel.on_scan_complete)

        self._worker.finding_found.connect(self._finding_cards_panel.add_finding)
        self._worker.scan_complete.connect(self._finding_cards_panel.on_scan_complete)

        self._worker.tool_started.connect(lambda name: self._status_label.setText(f"{name} — running…"))
        self._worker.tool_finished.connect(lambda name, n: self._status_label.setText(f"{name} — {n} items"))
        self._worker.tool_failed.connect(lambda name, msg: self._log(f"[FAILED] {name}: {msg}"))
        self._worker.log_line.connect(self._log)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_failed.connect(self._on_scan_failed)

        self._start_btn.setText("■  Cancel")
        self._terminal_panel.clear()
        self._worker.start()

    def _log(self, line: str):
        self._terminal_panel.appendPlainText(line)

    def _on_scan_complete(self, hosts: int, findings: int):
        self._status_label.setText(f"Complete — {hosts} hosts, {findings} findings")
        self._start_btn.setText("▶  Start Scan")

    def _on_scan_failed(self, msg: str):
        self._status_label.setText(f"Stopped: {msg}")
        self._start_btn.setText("▶  Start Scan")
```

- [ ] **Step 4: Run all scan_view tests**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py -v
```
Expected: all 15 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short -v
```
Expected: all tests PASS, zero failures.

- [ ] **Step 6: Commit and push**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/scan_view.py tests/test_screen_scan_view.py
git commit -m "feat: wire live visual widgets into ScanViewScreen

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
git push origin master
```

---

## Self-Review Notes

**Spec coverage:**
- PipelineTracker: 9 nodes, idle/running/done/failed states, pulse animation ✓ (Task 1)
- SeverityRings: 4 rings, QPainter donut, animated fill on add_finding ✓ (Task 2)
- FindingCards: slide-in animation, cap 200, summary card, newest on top ✓ (Task 3)
- AttackGraph: FR layout, 60fps timer, 5 node types, reset/add_host/add_finding ✓ (Task 4)
- ScanViewScreen wiring: all 4 widgets, all signals connected ✓ (Task 5)
- Signal→widget mapping from spec Section 2: all 11 connections present in Task 5 ✓

**Type consistency:**
- `PipelineTracker.on_tool_started(name: str)` — matches `tool_started = pyqtSignal(str)` ✓
- `PipelineTracker.on_tool_finished(name: str, count: int)` — matches `tool_finished = pyqtSignal(str, int)` ✓
- `AttackGraph.add_host(host)` / `add_finding(finding)` — match `host_found(object)` / `finding_found(object)` ✓
- `SeverityRings.add_finding(finding)` — finding.severity used as key ✓
- `FindingCards.add_finding(finding)` — finding.tool, .severity, .title, .description used ✓
- `_make_db()` referenced in appended scan_view tests — already defined earlier in that file ✓
