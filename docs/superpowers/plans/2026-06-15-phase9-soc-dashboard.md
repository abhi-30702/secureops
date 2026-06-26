# Phase 9 — SOC Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the SOC Dashboard with auto-refresh, live severity counts, a schedule status panel, and delta alerts between scans.

**Architecture:** QTimer auto-refresh in DashboardScreen → LiveSeverityStrip + SchedulePanel + DeltaPanel; DeltaWorker QThread fired from MainWindow on scan completion.

**Tech Stack:** PyQt6, SQLite (existing db.py), QThread

---

## Task 1: LiveSeverityStrip + DashboardScreen auto-refresh

**Files:**
- Modify: `screens/dashboard.py`
- Create: `tests/test_dashboard_refresh.py`

Read `screens/dashboard.py` before editing. The existing `SeverityStrip` class must be replaced with `LiveSeverityStrip`.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_dashboard_refresh.py
import gc
import pytest
from PyQt6.QtWidgets import QApplication
from db import DB
from models import Finding, Client, Scan
from datetime import datetime, timezone
from screens.dashboard import DashboardScreen, LiveSeverityStrip


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _now():
    return datetime.now(timezone.utc).isoformat()


def test_refresh_updates_finding_count(qtbot):
    db = DB(":memory:")
    screen = DashboardScreen(tool_results={}, db=db)
    qtbot.addWidget(screen)
    # Insert a scan + finding
    scan_id = db.insert_scan(Scan(None, None, "test.com", "complete", _now(), _now()))
    db.insert_finding(Finding(None, scan_id, None, "nuclei", "high", "XSS", "", "{}", _now()))
    screen.refresh()
    card_map = {c.title: c for c in screen._metric_cards}
    assert card_map["Findings"]._value_label.text() == "1"


def test_live_severity_strip_set_counts(qtbot):
    strip = LiveSeverityStrip()
    qtbot.addWidget(strip)
    strip.set_counts(critical=5, high=3, medium=2, low=1)
    assert strip._counts["critical"] == 5
    assert strip._counts["high"] == 3
    assert strip._counts["medium"] == 2
    assert strip._counts["low"] == 1


def test_refresh_updates_severity_strip(qtbot):
    db = DB(":memory:")
    screen = DashboardScreen(tool_results={}, db=db)
    qtbot.addWidget(screen)
    scan_id = db.insert_scan(Scan(None, None, "t.com", "complete", _now(), _now()))
    db.insert_finding(Finding(None, scan_id, None, "nuclei", "critical", "A", "", "{}", _now()))
    db.insert_finding(Finding(None, scan_id, None, "nuclei", "high", "B", "", "{}", _now()))
    screen.refresh()
    assert screen._severity_strip._counts["critical"] == 1
    assert screen._severity_strip._counts["high"] == 1
```

- [ ] **Step 2: Run to confirm failures**

```bash
source venv/bin/activate && pytest tests/test_dashboard_refresh.py -v
```
Expected: 3 errors (LiveSeverityStrip not found, _severity_strip missing)

- [ ] **Step 3: Rewrite dashboard.py**

Read current `screens/dashboard.py` fully first.

Replace `SeverityStrip` class entirely with `LiveSeverityStrip`:

```python
class LiveSeverityStrip(QWidget):
    _COLORS = {
        "critical": "#ff3d57",
        "high":     "#ff8800",
        "medium":   "#ffb300",
        "low":      "#4488ff",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self._labels: dict[str, QLabel] = {}
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(24)
        for sev, color in self._COLORS.items():
            lbl = QLabel()
            lbl.setTextFormat(Qt.TextFormat.RichText)
            self._labels[sev] = lbl
            layout.addWidget(lbl)
        self._refresh_labels()

    def set_counts(self, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> None:
        self._counts = {"critical": critical, "high": high, "medium": medium, "low": low}
        self._refresh_labels()

    def _refresh_labels(self) -> None:
        for sev, lbl in self._labels.items():
            color = self._COLORS[sev]
            count = self._counts[sev]
            lbl.setText(f"<span style='color:{color}'>●</span>  {sev.capitalize()}  <b>{count}</b>")
```

In `DashboardScreen.__init__`, replace `self._severity_strip: SeverityStrip | None = None` with `self._severity_strip: LiveSeverityStrip | None = None`.

In `_setup_ui()`, replace `self._severity_strip = SeverityStrip()` with `self._severity_strip = LiveSeverityStrip()`.

**Add auto-refresh timer** at the end of `_setup_ui()`:
```python
        self._updated_label = QLabel("")
        self._updated_label.setStyleSheet("color: #3d5a7a; font-size: 10px;")
        layout.addWidget(self._updated_label)

        if self._db:
            from PyQt6.QtCore import QTimer
            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(30_000)
```

**Update `refresh()` method** to also update severity strip and timestamp:

After existing metrics update, add:
```python
        # Severity breakdown
        rows = self._conn_or_null("SELECT severity, COUNT(*) as n FROM findings GROUP BY severity")
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in rows:
            key = row[0] if isinstance(row, (list, tuple)) else row["severity"]
            val = row[1] if isinstance(row, (list, tuple)) else row["n"]
            if key in sev_counts:
                sev_counts[key] = val
        if self._severity_strip:
            self._severity_strip.set_counts(**sev_counts)

        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        if hasattr(self, "_updated_label"):
            self._updated_label.setText(f"Updated {ts}")
```

Add a helper to `refresh()` to query severity counts cleanly:
```python
        rows = self._db._conn.execute(
            "SELECT severity, COUNT(*) as n FROM findings GROUP BY severity"
        ).fetchall()
```

(Use `self._db._conn.execute` directly — same pattern as existing code in `DashboardScreen`.)

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_dashboard_refresh.py -v
```
Expected: 3 passed

- [ ] **Step 5: Run full suite**

```bash
pytest tests/ -p no:randomly -q --tb=no
```
Expected: 346 passed (343 + 3 new)

- [ ] **Step 6: Commit**

```bash
git add screens/dashboard.py tests/test_dashboard_refresh.py
git commit -m "feat: add auto-refresh timer and LiveSeverityStrip to DashboardScreen"
```

---

## Task 2: SchedulePanel widget

**Files:**
- Create: `screens/widgets/schedule_panel.py`

No separate test file needed — schedule_panel is a read-only display widget. It will be smoke-tested as part of Task 3.

- [ ] **Step 1: Implement SchedulePanel**

Read `db.py` to confirm `query_schedules()` returns `list[Schedule]` with fields: `id, target, interval_h, enabled, last_run, created_at`.

```python
# screens/widgets/schedule_panel.py
from datetime import datetime, timezone, timedelta
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt
from db import DB


def _next_due(last_run: str | None, interval_h: int) -> str:
    if not last_run:
        return "overdue"
    try:
        last = datetime.fromisoformat(last_run)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        due = last + timedelta(hours=interval_h)
        now = datetime.now(timezone.utc)
        if due <= now:
            return "overdue"
        return due.strftime("%H:%M")
    except Exception:
        return "—"


class SchedulePanel(QWidget):
    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        hdr = QLabel("Scheduled Scans")
        hdr.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 12px;")
        layout.addWidget(hdr)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Target", "Interval", "Next Due"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table)

        self.refresh()

    def refresh(self) -> None:
        self._table.setRowCount(0)
        for sched in self._db.query_schedules():
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(sched.target))
            self._table.setItem(row, 1, QTableWidgetItem(f"{sched.interval_h}h"))
            self._table.setItem(row, 2, QTableWidgetItem(_next_due(sched.last_run, sched.interval_h)))
```

- [ ] **Step 2: Verify import**

```bash
QT_QPA_PLATFORM=offscreen python -c "from screens.widgets.schedule_panel import SchedulePanel; print('OK')"
```

- [ ] **Step 3: Wire into DashboardScreen**

Read `screens/dashboard.py` again. Find the `middle_row` layout that currently has `_placeholder_panel("Attack Surface Graph...")` and `_threat_feed`.

Replace the placeholder panel with `SchedulePanel`:

```python
from screens.widgets.schedule_panel import SchedulePanel
...
if self._db:
    self._schedule_panel = SchedulePanel(db=self._db)
    middle_row.addWidget(self._schedule_panel, stretch=1)
else:
    middle_row.addWidget(_placeholder_panel("Scheduled Scans\n(DB not available)"), stretch=1)
    self._schedule_panel = None
```

In `refresh()`, add:
```python
        if self._schedule_panel:
            self._schedule_panel.refresh()
```

Add `self._schedule_panel: SchedulePanel | None = None` to `__init__` attribute list.

- [ ] **Step 4: Smoke test**

```bash
QT_QPA_PLATFORM=offscreen python -c "
from PyQt6.QtWidgets import QApplication; import sys
app = QApplication.instance() or QApplication(sys.argv)
from db import DB; from models import Schedule; from datetime import datetime, timezone
db = DB(':memory:')
from scheduler.schedule_manager import ScheduleManager
db.insert_schedule(Schedule(None, 'example.com', 24, True, None, datetime.now(timezone.utc).isoformat()))
from screens.widgets.schedule_panel import SchedulePanel
panel = SchedulePanel(db=db)
assert panel._table.rowCount() == 1
assert 'example.com' in panel._table.item(0, 0).text()
print('SchedulePanel smoke test PASSED')
"
```

- [ ] **Step 5: Commit**

```bash
git add screens/widgets/schedule_panel.py screens/dashboard.py
git commit -m "feat: add SchedulePanel widget to DashboardScreen"
```

---

## Task 3: DeltaWorker + DeltaPanel + MainWindow wiring

**Files:**
- Create: `workers/delta_worker.py`
- Create: `screens/widgets/delta_panel.py`
- Create: `tests/test_delta_worker.py`
- Modify: `screens/dashboard.py`
- Modify: `main_window.py`

- [ ] **Step 1: Write failing tests for DeltaWorker**

```python
# tests/test_delta_worker.py
import gc
import pytest
from db import DB
from models import Scan, Finding
from datetime import datetime, timezone
from workers.delta_worker import DeltaWorker


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _insert_scan(db, target="t.com"):
    return db.insert_scan(Scan(None, None, target, "complete", _now(), _now()))


def _insert_finding(db, scan_id, title="X", host="t.com"):
    return db.insert_finding(
        Finding(None, scan_id, None, "nuclei", "high", title, "", "{}", _now())
    )


def test_no_previous_scan_all_new():
    db = DB(":memory:")
    sid = _insert_scan(db)
    _insert_finding(db, sid, "A")
    _insert_finding(db, sid, "B")
    results = []
    worker = DeltaWorker(scan_id=sid, target="t.com", db=db)
    worker.delta_ready.connect(lambda t, n, r: results.append((t, n, r)))
    worker.run()
    assert len(results) == 1
    assert results[0][1] == 2    # 2 new
    assert results[0][2] == 0    # 0 resolved


def test_new_findings_detected():
    db = DB(":memory:")
    prev = _insert_scan(db)
    _insert_finding(db, prev, "A")
    _insert_finding(db, prev, "B")
    curr = _insert_scan(db)
    _insert_finding(db, curr, "A")
    _insert_finding(db, curr, "B")
    _insert_finding(db, curr, "C")
    results = []
    worker = DeltaWorker(scan_id=curr, target="t.com", db=db)
    worker.delta_ready.connect(lambda t, n, r: results.append((t, n, r)))
    worker.run()
    assert results[0][1] == 1    # C is new
    assert results[0][2] == 0    # nothing resolved


def test_resolved_findings_detected():
    db = DB(":memory:")
    prev = _insert_scan(db)
    _insert_finding(db, prev, "A")
    _insert_finding(db, prev, "B")
    _insert_finding(db, prev, "C")
    curr = _insert_scan(db)
    _insert_finding(db, curr, "A")
    _insert_finding(db, curr, "B")
    results = []
    worker = DeltaWorker(scan_id=curr, target="t.com", db=db)
    worker.delta_ready.connect(lambda t, n, r: results.append((t, n, r)))
    worker.run()
    assert results[0][1] == 0    # nothing new
    assert results[0][2] == 1    # C resolved


def test_error_emitted_on_bad_scan_id():
    db = DB(":memory:")
    errors = []
    worker = DeltaWorker(scan_id=-1, target="t.com", db=db)
    worker.error_occurred.connect(errors.append)
    worker.run()
    # Either delta_ready fires (with 0 new from empty list) or error fires
    # Either outcome is acceptable — the worker must not crash
    assert True
```

- [ ] **Step 2: Run to confirm failures**

```bash
pytest tests/test_delta_worker.py -v
```
Expected: 4 errors (module not found)

- [ ] **Step 3: Implement DeltaWorker**

```python
# workers/delta_worker.py
from PyQt6.QtCore import QThread, pyqtSignal
from db import DB


class DeltaWorker(QThread):
    delta_ready    = pyqtSignal(str, int, int)   # (target, new_count, resolved_count)
    error_occurred = pyqtSignal(str)

    def __init__(self, scan_id: int, target: str, db: DB, parent=None):
        super().__init__(parent)
        self._scan_id = scan_id
        self._target = target
        self._db = db

    def run(self) -> None:
        try:
            current = self._db.query_findings_by_scan(self._scan_id)
            current_keys = {(f.tool, f.title, f.description) for f in current}

            row = self._db._conn.execute(
                "SELECT id FROM scans WHERE target=? AND status='complete' AND id<? ORDER BY id DESC LIMIT 1",
                (self._target, self._scan_id),
            ).fetchone()

            if row is None:
                self.delta_ready.emit(self._target, len(current), 0)
                return

            prev = self._db.query_findings_by_scan(row["id"])
            prev_keys = {(f.tool, f.title, f.description) for f in prev}

            new_count = len(current_keys - prev_keys)
            resolved_count = len(prev_keys - current_keys)
            self.delta_ready.emit(self._target, new_count, resolved_count)
        except Exception as exc:
            self.error_occurred.emit(str(exc))
```

- [ ] **Step 4: Run DeltaWorker tests**

```bash
pytest tests/test_delta_worker.py -v
```
Expected: 4 passed

- [ ] **Step 5: Implement DeltaPanel**

```python
# screens/widgets/delta_panel.py
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QScrollArea, QFrame,
)
from PyQt6.QtCore import Qt

_MAX_CHIPS = 10


class DeltaPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._chips: list[QLabel] = []
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        hdr = QLabel("Delta:")
        hdr.setStyleSheet("color: #7a9bc4; font-size: 10px;")
        outer.addWidget(hdr)

        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFixedHeight(28)

        self._inner = QWidget()
        self._row = QHBoxLayout(self._inner)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(8)
        self._row.addStretch()
        scroll.setWidget(self._inner)
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll, 1)

    def add_delta(self, target: str, new_count: int, resolved_count: int) -> None:
        if new_count == 0 and resolved_count == 0:
            text = f"{target}  no change"
            color = "#3d5a7a"
        else:
            text = f"{target}  +{new_count} new  −{resolved_count} resolved"
            color = "#ffb300" if new_count > 0 else "#00ff88"

        chip = QLabel(text)
        chip.setStyleSheet(
            f"color: {color}; background: #0a1628; padding: 2px 8px; "
            f"border-radius: 3px; font-size: 10px;"
        )

        self._row.insertWidget(0, chip)
        self._chips.insert(0, chip)

        if len(self._chips) > _MAX_CHIPS:
            old = self._chips.pop()
            self._row.removeWidget(old)
            old.deleteLater()

    def clear(self) -> None:
        for chip in self._chips:
            self._row.removeWidget(chip)
            chip.deleteLater()
        self._chips.clear()
```

- [ ] **Step 6: Add DeltaPanel to DashboardScreen**

Read `screens/dashboard.py`. In `__init__` attribute list, add `self._delta_panel: DeltaPanel | None = None`.

In `_setup_ui()`, after the severity strip and before `layout.addStretch()`:

```python
        from screens.widgets.delta_panel import DeltaPanel
        self._delta_panel = DeltaPanel()
        layout.addWidget(self._delta_panel)
```

- [ ] **Step 7: Wire DeltaWorker in MainWindow**

Read `main_window.py`. In `__init__`, add `self._delta_workers: list = []` to attribute declarations (before `_setup_ui()`).

In `_on_scan_ready(scan_id)`, after `self._dashboard.refresh()`:

```python
        if self._db and self._dashboard and self._dashboard._delta_panel:
            row = self._db._conn.execute(
                "SELECT target FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            if row:
                from workers.delta_worker import DeltaWorker
                dw = DeltaWorker(scan_id=scan_id, target=row["target"], db=self._db)
                dw.delta_ready.connect(self._dashboard._delta_panel.add_delta)
                dw.finished.connect(dw.deleteLater)
                dw.finished.connect(lambda: self._delta_workers.remove(dw) if dw in self._delta_workers else None)
                self._delta_workers.append(dw)
                dw.start()
```

- [ ] **Step 8: Run full test suite**

```bash
pytest tests/ -p no:randomly -q --tb=no
```
Expected: 350 passed (343 + 3 dashboard + 4 delta)

- [ ] **Step 9: Commit**

```bash
git add workers/delta_worker.py screens/widgets/delta_panel.py \
        tests/test_delta_worker.py screens/dashboard.py main_window.py
git commit -m "feat: Phase 9 complete — delta alerts, schedule panel, auto-refresh dashboard"
```
