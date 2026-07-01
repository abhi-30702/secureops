# Phase 9 — SOC Dashboard Design Spec

**Version:** 1.0  
**Date:** 2026-06-15  
**Owner:** Abhishek K — the organisation  
**Status:** Approved — ready to plan  

---

## 1. Overview

Phase 9 completes the SOC Dashboard by adding:
1. **Auto-refresh** — QTimer polls DB every 30 s, updates metric cards and severity strip with live data
2. **Live severity counts** — Fix the static SeverityStrip to show actual critical/high/medium/low counts
3. **Schedule status panel** — Shows registered scheduled scans with last_run and next_due timestamps
4. **Delta alerts** — Compare findings from the latest completed scan vs the previous scan for the same target; surface new and resolved findings

PRD requirements: FR-13 (auto-refresh), FR-14 (schedule status), FR-15 (delta alerts).

---

## 2. Architecture

```
DashboardScreen
  ├── MetricCard × 3  (Clients · Scans · Findings)
  ├── LiveSeverityStrip       [replaces SeverityStrip]
  ├── QHBoxLayout (middle row)
  │   ├── SchedulePanel       [new widget — left half]
  │   └── ThreatFeed          [existing — right half]
  ├── DeltaPanel              [new widget — bottom strip]
  └── QTimer (30 s) → refresh()

DeltaWorker (QThread)
  scan_id + target → DB → compare findings → emit signals
  Connected in MainWindow._on_scan_ready()
```

---

## 3. Auto-refresh (DashboardScreen changes)

### 3.1 QTimer

Add a `QTimer(self)` set to 30,000 ms. Connect to `self.refresh()`. Start on `__init__` only if `self._db` is set.

### 3.2 Last-updated label

Add a `QLabel` showing `"Updated HH:MM:SS"`. Set after each `refresh()` call.

### 3.3 LiveSeverityStrip (replaces SeverityStrip)

Replace static `SeverityStrip` with a stateful `LiveSeverityStrip` that has a `set_counts(critical, high, medium, low)` method.

```python
class LiveSeverityStrip(QWidget):
    def __init__(self, parent=None): ...
    def set_counts(self, critical: int, high: int, medium: int, low: int) -> None: ...
```

Layout: 4 horizontal chips, each `"● LABEL  N"` in severity colour. Updates in-place via `set_counts()`.

`refresh()` queries `db._conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")` and feeds results into `set_counts()`.

---

## 4. SchedulePanel (`screens/widgets/schedule_panel.py`)

A read-only table showing scheduled scans.

```python
class SchedulePanel(QWidget):
    def __init__(self, db: DB, parent=None): ...
    def refresh(self) -> None: ...
```

### Layout

```
QVBoxLayout
├── QLabel "Scheduled Scans"  (header)
└── QTableWidget (3 columns: Target | Interval | Last Run / Next Due)
    read-only, alternating row colours
```

### Data

- Loaded via `db.query_schedules()`
- "Last Run": `schedule.last_run[11:19]` or `"—"` if None
- "Next Due": compute from `last_run + interval_h * 3600 s`; format as `"HH:MM"` or `"overdue"` if past

### `refresh()` — reload table from DB. Called from `DashboardScreen.refresh()`.

---

## 5. DeltaWorker (`workers/delta_worker.py`)

```python
class DeltaWorker(QThread):
    delta_ready   = pyqtSignal(str, int, int)   # (target, new_count, resolved_count)
    error_occurred = pyqtSignal(str)

    def __init__(self, scan_id: int, target: str, db: DB, parent=None): ...
    def run(self) -> None: ...
```

**Algorithm:**

1. `current_findings = db.query_findings_by_scan(scan_id)` — Finding dataclass objects
2. Find previous scan: `SELECT id FROM scans WHERE target=? AND status='complete' AND id < ? ORDER BY id DESC LIMIT 1`
3. If no previous scan: `delta_ready.emit(target, len(current_findings), 0)` — all findings are "new"
4. `prev_findings = db.query_findings_by_scan(prev_scan_id)`
5. Compute keys as `(tool, title, host)` tuples
6. `new_count = len(current_keys - prev_keys)`
7. `resolved_count = len(prev_keys - current_keys)`
8. `delta_ready.emit(target, new_count, resolved_count)`

**Error handling:** wrap in try/except, emit `error_occurred` on failure.

---

## 6. DeltaPanel (`screens/widgets/delta_panel.py`)

A compact horizontal strip below ThreatFeed showing recent delta alerts.

```python
class DeltaPanel(QWidget):
    def __init__(self, parent=None): ...
    def add_delta(self, target: str, new_count: int, resolved_count: int) -> None: ...
    def clear(self) -> None: ...
```

### Layout

```
QHBoxLayout (scrollable)
  ├── QLabel "Delta Alerts:"
  └── Per-alert chip: "target.com  +N new  −R resolved"
      colour: green if 0 new, amber if new > 0
```

Each call to `add_delta()` prepends a chip. Keeps at most 10 chips.

---

## 7. MainWindow wiring

In `_on_scan_ready(scan_id)`, after loading the report:

```python
from workers.delta_worker import DeltaWorker
scan = ...  # get target from scan_id via db
target = db._conn.execute("SELECT target FROM scans WHERE id=?", (scan_id,)).fetchone()["target"]
delta_w = DeltaWorker(scan_id=scan_id, target=target, db=self._db)
delta_w.delta_ready.connect(self._dashboard._delta_panel.add_delta)
delta_w.finished.connect(delta_w.deleteLater)
delta_w.start()
self._delta_workers.append(delta_w)  # prevent GC
```

`_delta_workers` is a list on MainWindow, cleaned up when workers finish.

---

## 8. Testing

### `tests/test_dashboard_refresh.py` (3 tests)

| Test | What it checks |
|------|---------------|
| `test_refresh_updates_metric_cards` | Insert 2 findings; refresh → Findings card shows 2 |
| `test_live_severity_strip_set_counts` | set_counts(1,2,3,4) → labels show correct numbers |
| `test_schedule_panel_shows_schedules` | Insert a schedule; SchedulePanel.refresh() → table has 1 row |

### `tests/test_delta_worker.py` (4 tests)

| Test | What it checks |
|------|---------------|
| `test_no_previous_scan_all_new` | 1 scan, 3 findings → new=3, resolved=0 |
| `test_new_findings_detected` | prev scan 2 findings, current 3 → new=1, resolved=0 |
| `test_resolved_findings_detected` | prev scan 3 findings, current 2 → new=0, resolved=1 |
| `test_error_emitted_on_bad_scan_id` | scan_id=-1 → error_occurred fires |

---

## 9. File map

| Action | Path |
|--------|------|
| Modify | `screens/dashboard.py` (auto-refresh timer, LiveSeverityStrip, DeltaPanel ref, SchedulePanel ref) |
| Create | `screens/widgets/schedule_panel.py` |
| Create | `screens/widgets/delta_panel.py` |
| Create | `workers/delta_worker.py` |
| Modify | `main_window.py` (wire DeltaWorker in _on_scan_ready) |
| Create | `tests/test_dashboard_refresh.py` |
| Create | `tests/test_delta_worker.py` |

---

## 10. Constraints

- Auto-refresh timer is paused when DB is None — no crash on startup without DB
- DeltaWorker is a one-shot QThread per scan — created fresh each time, deleteLater on finished
- SchedulePanel is read-only — no editing (editing stays in Settings)
- Delta panel is display-only — max 10 chips, oldest dropped on overflow
- No new DB tables needed — uses existing `scans` and `findings`
