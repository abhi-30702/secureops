# Phase 5 — Continuous Monitoring (SOC) and Scheduling Design

**Date:** 2026-06-03  
**Status:** Approved  
**Phase:** 5 of 7

---

## Overview

Phase 5 makes the app a live SOC tool: the Dashboard shows real metrics from the DB, a ThreatFeed surfaces recent findings, and a ScheduleManager fires periodic re-scans of configured targets.

**Deliverables:**
- `Schedule` dataclass + `schedules` DB table + CRUD methods
- `ScheduleManager(QObject)` — polls schedules via 60s QTimer, emits `scan_due(str)`
- `ThreatFeed(QScrollArea)` — recent findings across all scans, color-coded
- `DashboardScreen` refresh — live Clients/Scans/Findings counts + ThreatFeed
- `SettingsScreen` schedule section — add/delete/enable schedules
- `ScanViewScreen.start_scan(target)` — programmatic scan trigger
- `MainWindow` wiring — ScheduleManager connected to Dashboard + ScanView

No changes to the scan engine or PDF export.

---

## 1. File Map

| File | Action |
|------|--------|
| `models.py` | Add `Schedule` dataclass |
| `db.py` | Add `schedules` table + 4 CRUD methods |
| `scheduler/__init__.py` | Create (empty) |
| `scheduler/schedule_manager.py` | Create `ScheduleManager(QObject)` |
| `screens/widgets/threat_feed.py` | Create `ThreatFeed(QScrollArea)` |
| `screens/dashboard.py` | Rewrite: accept `db`, live metrics, ThreatFeed |
| `screens/settings.py` | Modify: accept `db`, add schedule section |
| `screens/scan_view.py` | Modify: add `start_scan(target: str)` |
| `main_window.py` | Modify: pass `db` to Dashboard+Settings, wire ScheduleManager |
| `tests/test_db.py` | Append: 4 schedule CRUD tests |
| `tests/test_scheduler.py` | Create: 4 ScheduleManager tests |
| `tests/test_widget_threat_feed.py` | Create: 5 ThreatFeed tests |
| `tests/test_screen_dashboard.py` | Rewrite: live metrics tests |
| `tests/test_screen_settings.py` | Append: 3 schedule UI tests |
| `tests/test_screen_scan_view.py` | Append: 1 start_scan test |
| `tests/test_main_window.py` | Append: 1 dashboard-has-db test |

---

## 2. Data Model

### Schedule dataclass (models.py)

```python
@dataclass
class Schedule:
    id: int | None
    target: str
    interval_h: int      # hours between scans
    enabled: bool
    last_run: str | None # ISO timestamp or None if never run
    created_at: str
```

### schedules DB table (db.py)

```sql
CREATE TABLE IF NOT EXISTS schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL UNIQUE,
    interval_h  INTEGER NOT NULL DEFAULT 24,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run    TEXT,
    created_at  TEXT NOT NULL
);
```

### New DB methods

```python
def insert_schedule(self, schedule: Schedule) -> int: ...
def query_schedules(self) -> list[Schedule]: ...
def update_schedule(self, schedule_id: int, enabled: bool, last_run: str | None) -> None: ...
def delete_schedule(self, schedule_id: int) -> None: ...
```

---

## 3. ScheduleManager

```python
class ScheduleManager(QObject):
    scan_due = pyqtSignal(str)   # emits target when a scan is due

    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._check)
        self._timer.start(60_000)   # tick every 60 seconds

    def _check(self):
        now = datetime.now(timezone.utc)
        for schedule in self._db.query_schedules():
            if not schedule.enabled:
                continue
            if schedule.last_run is None:
                due = True
            else:
                last = datetime.fromisoformat(schedule.last_run)
                due = (now - last).total_seconds() >= schedule.interval_h * 3600
            if due:
                self._db.update_schedule(schedule.id, enabled=True,
                                         last_run=now.isoformat())
                self.scan_due.emit(schedule.target)

    def stop(self):
        self._timer.stop()
```

**Design notes:**
- `QTimer(self)` — parented, stops on destroy
- `update_schedule` writes `last_run` before emitting signal, preventing double-fire if check runs again before the scan completes
- Emits one signal per due target per tick

---

## 4. ThreatFeed

**Structure:** `QScrollArea` → `QWidget` → `QVBoxLayout`

**Populates** from `query_recent_findings(limit=20)` — a new DB helper that returns the 20 most recent findings across all scans, ordered by `created_at DESC`.

**Each card shows:**
- Coloured left border (severity colour)
- Finding title (bold) + tool (muted)
- Target domain from scan
- Timestamp

**Public interface:**
```python
def refresh(self, db: DB) -> None: ...
def clear(self) -> None: ...
```

**New DB method:**
```python
def query_recent_findings(self, limit: int = 20) -> list[Finding]: ...
```

---

## 5. DashboardScreen Changes

### Constructor change
```python
def __init__(self, tool_results: dict, db=None, parent=None):
```

### New attributes
```python
self._db: DB | None
self._threat_feed: ThreatFeed
```

### Metric cards update
The 3 cards (Clients, Scans, Findings) each store a reference to their value `QLabel`.

`refresh()` queries the DB:
```python
def refresh(self):
    if not self._db:
        return
    n_clients = len(self._db.query_clients())
    n_scans = len(self._db.query_scans_by_client(None)) + sum(
        len(self._db.query_scans_by_client(c.id))
        for c in self._db.query_clients()
    )
    n_findings = self._db.query_recent_findings(limit=9999)  # count all
    # update card value labels
    self._threat_feed.refresh(self._db)
```

### Layout change
Replace `_placeholder_panel("Threat Feed\nLive in Phase 3")` with `ThreatFeed` instance.
Keep "Attack Surface Graph" placeholder (reserved for future).

---

## 6. SettingsScreen Changes

### Constructor change
```python
def __init__(self, tool_results: dict, db=None, parent=None):
```

### New schedule section (below tool list)
```
┌─ SCHEDULED SCANS ──────────────────────────────────────┐
│  Target: [________________]  Interval: [Every 24h ▼]   │
│  [+ Add Schedule]                                        │
│                                                          │
│  example.com      Every 24h  ● Enabled   [Delete]       │
│  target2.com      Every 4h   ○ Disabled  [Delete]       │
└──────────────────────────────────────────────────────────┘
```

**Widgets:**
- `_schedule_target: QLineEdit`
- `_schedule_interval: QComboBox` — ["Every 1h", "Every 4h", "Every 24h"] → [1, 4, 24]
- Add button: calls `db.insert_schedule(...)`, refreshes list
- Schedule list: one row per schedule with enable toggle + delete button

---

## 7. ScanViewScreen.start_scan

```python
def start_scan(self, target: str) -> None:
    """Programmatically start a scan. No-op if a scan is already running."""
    if self._worker and self._worker.isRunning():
        return
    if not self._db:
        return
    self._target_input.setText(target)
    self._on_start_cancel()
```

---

## 8. MainWindow Changes

```python
# In __init__:
self._schedule_manager: ScheduleManager | None = None

# In _setup_ui:
self._stack.addWidget(DashboardScreen(self._tool_results, db=self._db))  # 0
self._stack.addWidget(SettingsScreen(self._tool_results, db=self._db))   # 4

# After stack setup:
if self._db:
    self._schedule_manager = ScheduleManager(db=self._db, parent=self)
    self._schedule_manager.scan_due.connect(self._on_scan_due)

# Extend _on_scan_ready to also refresh dashboard:
def _on_scan_ready(self, scan_id: int):
    self._report.load_scan(scan_id)
    self._stack.setCurrentIndex(3)
    dashboard = self._stack.widget(0)
    if hasattr(dashboard, "refresh"):
        dashboard.refresh()
```

`_on_scan_due`:
```python
def _on_scan_due(self, target: str):
    self._stack.setCurrentIndex(2)
    self._scan_view.start_scan(target)
```

---

## 9. Testing

| File | Coverage |
|------|----------|
| `tests/test_db.py` | insert_schedule, query_schedules, update_schedule, delete_schedule |
| `tests/test_scheduler.py` | scan_due emitted when due, not emitted when disabled, not emitted when not yet due, last_run updated |
| `tests/test_widget_threat_feed.py` | starts empty, refresh populates, clear empties, max 20 cards |
| `tests/test_screen_dashboard.py` | has ThreatFeed, refresh updates metric count labels |
| `tests/test_screen_settings.py` | has schedule section, add schedule inserts to db |
| `tests/test_screen_scan_view.py` | start_scan sets target and triggers scan |
| `tests/test_main_window.py` | dashboard widget gets db |

---

## 10. PRD Requirements Covered

| ID | Requirement |
|----|-------------|
| FR-21 | Scheduled re-scans — ScheduleManager, schedules table, Settings UI |
| FR-22 | Dashboard surfaces new threats — ThreatFeed, DashboardScreen.refresh() |
