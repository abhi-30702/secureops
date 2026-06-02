# Phase 3 — Live Visuals Design

**Date:** 2026-06-02
**Status:** Approved
**Phase:** 3 of 7

---

## Overview

Phase 3 replaces the 4 placeholder panels in `ScanViewScreen` with live visual widgets driven by the `ScanWorker` signals already emitted in Phase 2. No changes to the scan engine — this phase is purely UI.

**Deliverables:**
- `PipelineTracker` — 9 tool nodes, pulsing while active, green/red on completion
- `AttackGraph` — force-directed network graph (Fruchterman-Reingold, 60fps)
- `SeverityRings` — 4 animated QPainter donut charts
- `FindingCards` — slide-in finding card stream, newest on top
- Updated `ScanViewScreen` wiring all 4 widgets to ScanWorker signals

---

## 1. File Structure

```
screens/widgets/
  __init__.py
  pipeline_tracker.py   — PipelineTracker(QWidget)
  attack_graph.py       — AttackGraph(QWidget) using pyqtgraph
  severity_rings.py     — SeverityRings(QWidget) using QPainter
  finding_cards.py      — FindingCards(QScrollArea)
```

Existing files modified:
- `screens/scan_view.py` — replace 4 QFrame placeholders with widget instances, wire signals

New test files:
- `tests/test_widget_pipeline_tracker.py`
- `tests/test_widget_attack_graph.py`
- `tests/test_widget_severity_rings.py`
- `tests/test_widget_finding_cards.py`
- 4 new assertions appended to `tests/test_screen_scan_view.py`

---

## 2. Signal → Widget Mapping

| ScanWorker signal | Widget method |
|-------------------|---------------|
| `tool_started(str)` | `PipelineTracker.on_tool_started(name)` |
| `tool_finished(str, int)` | `PipelineTracker.on_tool_finished(name, count)` |
| `tool_failed(str, str)` | `PipelineTracker.on_tool_failed(name, msg)` |
| `host_found(object)` | `AttackGraph.add_host(host)` |
| `finding_found(object)` | `AttackGraph.add_finding(finding)`, `SeverityRings.add_finding(finding)`, `FindingCards.add_finding(finding)` |
| `scan_complete(int, int)` | all four `.on_scan_complete()` |

Each widget exposes a `reset()` method called at the start of each new scan.

---

## 3. PipelineTracker

### Layout

```
[subfinder]→[dnsx]→[naabu]→[httpx]→[katana]→[nuclei]
                      ↓
              [nmap] [nikto] [testssl]
```

Arrows are `QLabel("→")` spacers. The parallel tail sits in a second `QHBoxLayout` below the main chain, left-aligned under `naabu`.

### Node anatomy

Each node is a `QFrame` containing:
- Status dot `QLabel("●")` — coloured by state
- Tool name `QLabel` — monospace
- Count `QLabel` — e.g. `"23 hosts"`, hidden when idle

### Node states

| State | Dot colour | Animation |
|-------|-----------|-----------|
| idle | `#2d4a6b` (dark grey) | none |
| running | `#00d4ff` (cyan) | opacity 1.0→0.3→1.0, 600ms loop |
| done | `#00ff88` (green) | none |
| failed | `#ff4444` (red) | none |

The pulsing effect uses `QPropertyAnimation` on the dot label's `windowOpacity`. Animation stops and dot goes solid on `on_tool_finished` or `on_tool_failed`.

### Public interface

```python
def on_tool_started(self, name: str): ...
def on_tool_finished(self, name: str, count: int): ...
def on_tool_failed(self, name: str, msg: str): ...
def on_scan_complete(self, hosts: int, findings: int): ...
def reset(self): ...
```

---

## 4. AttackGraph

### Technology

`pyqtgraph.GraphicsLayoutWidget` containing a `ViewBox`. Nodes rendered as `ScatterPlotItem`, edges as line segments drawn with `pyqtgraph.PlotCurveItem` or `GraphItem`. Node labels via `TextItem`.

### Node types

| Type | Colour | Created by |
|------|--------|-----------|
| Target | `#00d4ff` cyan | `reset()` — one per scan |
| Subdomain | `#4488ff` blue | `add_host()` where `host.subdomain` set |
| Host/IP | `#00ff88` green | `add_host()` where `host.ip` and `host.port` set |
| URL | `#64748b` grey | `add_host()` where `host.url` set |
| Finding | severity colour | `add_finding()` |

Finding node colours: critical=`#ff4444`, high=`#ff8800`, medium=`#ffcc00`, low=`#4488ff`, info=`#64748b`.

### Physics — Fruchterman-Reingold

`QTimer` fires every 16ms (60fps). Each tick:

1. **Repulsion** — for every pair (u, v): `F_rep = k² / dist(u,v)`, direction away from v
2. **Attraction** — for every edge (u, v): `F_att = dist(u,v)² / k`, direction toward v
3. **Gravity** — weak pull toward canvas center: `F_grav = 0.01 * dist_to_center`
4. **Displacement** — clamp each node's movement to `min(|F|, temperature)`
5. **Cool** — `temperature *= 0.98` each tick

Where `k = sqrt(canvas_area / n_nodes)`.

**On new node arrival:** temperature reheats to `canvas_width * 0.2` to allow the graph to reshuffling around the new node, then re-cools naturally.

**On `on_scan_complete()`:** timer stops, graph freezes.

### Edge rules

- Target → Subdomain (for each subdomain discovered by subfinder)
- Subdomain → Host/IP (dnsx resolution)
- Host/IP → URL (httpx/katana)
- Host/IP → Finding (nuclei/nmap/nikto/testssl findings linked to host)

Edges are best-effort — if the parent node isn't found (e.g. subdomain not yet resolved), the new node connects to the target as fallback.

### Public interface

```python
def add_host(self, host): ...
def add_finding(self, finding): ...
def on_scan_complete(self, hosts: int, findings: int): ...
def reset(self): ...
```

---

## 5. SeverityRings

### Layout

4 donut charts in a `QHBoxLayout`, centred. Each chart is 110×110px.

### Drawing (QPainter)

Per ring, `paintEvent` draws:
1. Background circle arc — full 360°, colour `#1e2d40`, pen width 12px
2. Filled arc — `(count / max(count, 10)) * 360°`, severity colour, pen width 12px, starting at 12 o'clock (270°)
3. Count number — centered, bold, white, 22px
4. Severity label — below chart, 10px, muted grey

### Animation

`_fill: float` property per ring (0.0–1.0). `add_finding()` increments count and fires a `QPropertyAnimation` on `_fill` from current value to `new_count / max(new_count, 10)` over 300ms. `paintEvent` uses `_fill * 360°` for the arc sweep angle.

### Severity colours

| Severity | Colour |
|----------|--------|
| Critical | `#ff4444` |
| High | `#ff8800` |
| Medium | `#ffcc00` |
| Low | `#4488ff` |

### Public interface

```python
def add_finding(self, finding): ...
def on_scan_complete(self, hosts: int, findings: int): ...
def reset(self): ...
```

---

## 6. FindingCards

### Structure

`QScrollArea` → `QWidget` → `QVBoxLayout` (cards inserted at index 0, newest on top).

### Card anatomy

Each card is a `QFrame` with:
- 3px coloured left border (severity colour via stylesheet)
- Top line: tool name + timestamp — `QLabel`, 10px, muted
- Title line: finding title — `QLabel`, 13px, bold white, elided to 1 line
- Description: `QLabel`, 11px, muted grey, max 2 lines, word wrap

Card fixed height: 70px.

### Slide-in animation

On `add_finding()`:
1. Card inserted at layout index 0
2. `QPropertyAnimation` on `maximumHeight`: 0 → 70px, duration 250ms, `OutCubic` easing
3. Simultaneous `QGraphicsOpacityEffect` fade: 0.0 → 1.0, same duration
4. Scroll area scrolls to top after animation starts

### Cap

When card count exceeds 200, remove the last widget from the layout before inserting the new one.

### Scan complete card

`on_scan_complete()` inserts a special summary card at top — cyan border, title `"Scan complete"`, description `"{hosts} hosts discovered, {findings} findings"`.

### Public interface

```python
def add_finding(self, finding): ...
def on_scan_complete(self, hosts: int, findings: int): ...
def reset(self): ...
```

---

## 7. ScanViewScreen Changes

### Attribute type changes

```python
# Phase 2 → Phase 3
self._pipeline_panel:      QFrame       → PipelineTracker
self._attack_graph_panel:  QFrame       → AttackGraph
self._severity_panel:      QFrame       → SeverityRings
self._finding_cards_panel: QFrame       → FindingCards
```

### New signal wiring in `_on_start_cancel()`

```python
# Reset all widgets
self._pipeline_panel.reset()
self._attack_graph_panel.reset()
self._severity_panel.reset()
self._finding_cards_panel.reset()

# Pipeline tracker
self._worker.tool_started.connect(self._pipeline_panel.on_tool_started)
self._worker.tool_finished.connect(self._pipeline_panel.on_tool_finished)
self._worker.tool_failed.connect(self._pipeline_panel.on_tool_failed)
self._worker.scan_complete.connect(self._pipeline_panel.on_scan_complete)

# Attack graph
self._worker.host_found.connect(self._attack_graph_panel.add_host)
self._worker.finding_found.connect(self._attack_graph_panel.add_finding)
self._worker.scan_complete.connect(self._attack_graph_panel.on_scan_complete)

# Severity rings
self._worker.finding_found.connect(self._severity_panel.add_finding)
self._worker.scan_complete.connect(self._severity_panel.on_scan_complete)

# Finding cards
self._worker.finding_found.connect(self._finding_cards_panel.add_finding)
self._worker.scan_complete.connect(self._finding_cards_panel.on_scan_complete)
```

---

## 8. Testing

| File | Coverage |
|------|----------|
| `tests/test_widget_pipeline_tracker.py` | idle→running→done→failed state transitions, count label update |
| `tests/test_widget_attack_graph.py` | node count after add_host/add_finding, timer stops on scan_complete |
| `tests/test_widget_severity_rings.py` | correct ring incremented per severity, counts start at 0, 4 rings present |
| `tests/test_widget_finding_cards.py` | card added on add_finding, newest at top, cap at 200, summary card on scan_complete |
| `tests/test_screen_scan_view.py` | 4 new assertions: each panel is the correct widget type |

Animation timing not tested — `QPropertyAnimation` does not run meaningfully headless. Tests cover data state only.

---

## 9. PRD Requirements Covered

| ID | Requirement | Widget |
|----|-------------|--------|
| FR-11 | Report view updates in real time | FindingCards, SeverityRings |
| FR-12 | Severity counts animate as findings arrive | SeverityRings |
| FR-13 | On completion, view transitions to settled state | all `.on_scan_complete()` |
| §4.4 | Pipeline tracker — nodes pulse, green on done | PipelineTracker |
| §4.4 | Attack-surface graph — animated, force-directed | AttackGraph |
| §4.4 | Severity rings — animated counters | SeverityRings |
| §4.4 | Streaming finding cards — slide in, colour-coded | FindingCards |
