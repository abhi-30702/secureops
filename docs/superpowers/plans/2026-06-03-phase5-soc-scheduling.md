# Phase 5 — Continuous Monitoring (SOC) and Scheduling Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement task-by-task.

**Goal:** Add scheduled re-scans and live SOC dashboard. Three tasks: DB+scheduler, ThreatFeed+Dashboard, Settings+wiring.

---

## File Map

| File | Action |
|------|--------|
| `models.py` | Add `Schedule` dataclass |
| `db.py` | Add schedules table + 4 CRUD + `query_recent_findings` |
| `scheduler/__init__.py` | Create (empty) |
| `scheduler/schedule_manager.py` | `ScheduleManager(QObject)` |
| `screens/widgets/threat_feed.py` | `ThreatFeed(QScrollArea)` |
| `screens/dashboard.py` | Rewrite: db, live metrics, ThreatFeed |
| `screens/settings.py` | Modify: db, schedule section |
| `screens/scan_view.py` | Modify: `start_scan(target)` |
| `main_window.py` | Modify: wire all |
| `tests/test_db.py` | Append: schedule CRUD tests |
| `tests/test_scheduler.py` | Create |
| `tests/test_widget_threat_feed.py` | Create |
| `tests/test_screen_dashboard.py` | Rewrite |
| `tests/test_screen_settings.py` | Append |
| `tests/test_screen_scan_view.py` | Append |
| `tests/test_main_window.py` | Append |

---

## Task 1: Schedule model + DB + ScheduleManager

**Files:**
- Modify: `models.py`
- Modify: `db.py`
- Create: `scheduler/__init__.py`
- Create: `scheduler/schedule_manager.py`
- Modify: `tests/test_db.py` (append)
- Create: `tests/test_scheduler.py`

- [ ] **Step 1: Add `Schedule` to `models.py`**

Read models.py first. Append after the `Finding` dataclass:

```python
@dataclass
class Schedule:
    id: int | None
    target: str
    interval_h: int
    enabled: bool
    last_run: str | None
    created_at: str
```

- [ ] **Step 2: Add schedules table + CRUD + query_recent_findings to `db.py`**

Read db.py first.

1. Add to `_SCHEMA` (append another CREATE TABLE statement):
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

2. Update the `from models import` line to also import `Schedule`.

3. Append these methods to the `DB` class:

```python
def insert_schedule(self, schedule: "Schedule") -> int:
    with self._lock:
        cur = self._conn.execute(
            "INSERT INTO schedules (target, interval_h, enabled, last_run, created_at) VALUES (?,?,?,?,?)",
            (schedule.target, schedule.interval_h, 1 if schedule.enabled else 0,
             schedule.last_run, schedule.created_at),
        )
        self._conn.commit()
        return cur.lastrowid

def query_schedules(self) -> "list[Schedule]":
    rows = self._conn.execute("SELECT * FROM schedules ORDER BY id").fetchall()
    return [Schedule(id=r["id"], target=r["target"], interval_h=r["interval_h"],
                     enabled=bool(r["enabled"]), last_run=r["last_run"],
                     created_at=r["created_at"]) for r in rows]

def update_schedule(self, schedule_id: int, enabled: bool,
                    last_run: str | None) -> None:
    with self._lock:
        self._conn.execute(
            "UPDATE schedules SET enabled=?, last_run=? WHERE id=?",
            (1 if enabled else 0, last_run, schedule_id),
        )
        self._conn.commit()

def delete_schedule(self, schedule_id: int) -> None:
    with self._lock:
        self._conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
        self._conn.commit()

def query_recent_findings(self, limit: int = 20) -> "list[Finding]":
    rows = self._conn.execute(
        "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [Finding(id=r["id"], scan_id=r["scan_id"], host_id=r["host_id"],
                    tool=r["tool"], severity=r["severity"], title=r["title"],
                    description=r["description"] or "", raw_json=r["raw_json"] or "",
                    created_at=r["created_at"]) for r in rows]
```

Note: use string annotations `"Schedule"` and `"list[Schedule]"` to avoid circular import issues, OR just import Schedule at the top — it's the same file so no circular issue. Import `Schedule` in the `from models import` line.

- [ ] **Step 3: Create `scheduler/__init__.py`** — empty file.

- [ ] **Step 4: Write failing tests**

Append to `tests/test_db.py`:
```python
from models import Schedule


def test_insert_and_query_schedule(db):
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    sid = db.insert_schedule(s)
    schedules = db.query_schedules()
    assert len(schedules) == 1
    assert schedules[0].target == "example.com"
    assert schedules[0].id == sid


def test_update_schedule(db):
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    sid = db.insert_schedule(s)
    db.update_schedule(sid, enabled=False, last_run="2026-06-03T10:00:00")
    schedules = db.query_schedules()
    assert schedules[0].enabled is False
    assert schedules[0].last_run == "2026-06-03T10:00:00"


def test_delete_schedule(db):
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    sid = db.insert_schedule(s)
    db.delete_schedule(sid)
    assert db.query_schedules() == []


def test_query_recent_findings(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T10:00:00",
                              finished_at=None))
    for i in range(5):
        db.insert_finding(Finding(id=None, scan_id=sid, host_id=None, tool="nuclei",
                                  severity="high", title=f"Finding {i}", description="",
                                  raw_json="{}", created_at=f"2026-06-03T10:0{i}:00"))
    findings = db.query_recent_findings(limit=3)
    assert len(findings) == 3
```

Create `tests/test_scheduler.py`:
```python
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from models import Schedule
from db import DB
from scheduler.schedule_manager import ScheduleManager


def _make_db() -> DB:
    return DB(":memory:")


def test_schedule_manager_emits_scan_due_when_overdue(qtbot):
    db = _make_db()
    past = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=past, created_at="2026-06-03T00:00:00")
    db.insert_schedule(s)
    manager = ScheduleManager(db=db)
    emitted = []
    manager.scan_due.connect(emitted.append)
    manager._check()
    assert emitted == ["example.com"]


def test_schedule_manager_does_not_emit_when_not_due(qtbot):
    db = _make_db()
    recent = datetime.now(timezone.utc).isoformat()
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=recent, created_at="2026-06-03T00:00:00")
    db.insert_schedule(s)
    manager = ScheduleManager(db=db)
    emitted = []
    manager.scan_due.connect(emitted.append)
    manager._check()
    assert emitted == []


def test_schedule_manager_does_not_emit_when_disabled(qtbot):
    db = _make_db()
    past = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=False,
                 last_run=past, created_at="2026-06-03T00:00:00")
    db.insert_schedule(s)
    manager = ScheduleManager(db=db)
    emitted = []
    manager.scan_due.connect(emitted.append)
    manager._check()
    assert emitted == []


def test_schedule_manager_emits_when_never_run(qtbot):
    db = _make_db()
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    db.insert_schedule(s)
    manager = ScheduleManager(db=db)
    emitted = []
    manager.scan_due.connect(emitted.append)
    manager._check()
    assert "example.com" in emitted
```

- [ ] **Step 5: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_db.py::test_insert_and_query_schedule tests/test_scheduler.py -v
```

Expected: failures for missing ScheduleManager.

- [ ] **Step 6: Write `scheduler/schedule_manager.py`**

```python
from datetime import datetime, timezone
from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from db import DB


class ScheduleManager(QObject):
    scan_due = pyqtSignal(str)

    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._check)
        self._timer.start(60_000)

    def _check(self):
        now = datetime.now(timezone.utc)
        for schedule in self._db.query_schedules():
            if not schedule.enabled:
                continue
            if schedule.last_run is None:
                due = True
            else:
                try:
                    last = datetime.fromisoformat(schedule.last_run)
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    due = (now - last).total_seconds() >= schedule.interval_h * 3600
                except (ValueError, TypeError):
                    due = True
            if due:
                self._db.update_schedule(schedule.id, enabled=True,
                                         last_run=now.isoformat())
                self.scan_due.emit(schedule.target)

    def stop(self):
        self._timer.stop()
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_db.py tests/test_scheduler.py -v
```

All must pass (4 new db tests + 4 scheduler tests).

- [ ] **Step 8: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

All tests must pass.

- [ ] **Step 9: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add models.py db.py scheduler/__init__.py scheduler/schedule_manager.py tests/test_db.py tests/test_scheduler.py
git commit -m "feat: Schedule model, DB CRUD, ScheduleManager with 60s poll

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: ThreatFeed + Dashboard refresh

**Files:**
- Create: `screens/widgets/threat_feed.py`
- Rewrite: `screens/dashboard.py`
- Create: `tests/test_widget_threat_feed.py`
- Rewrite: `tests/test_screen_dashboard.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_widget_threat_feed.py`:
```python
from models import Finding, Scan
from db import DB
from screens.widgets.threat_feed import ThreatFeed


def _make_db_with_findings(n: int) -> DB:
    db = DB(":memory:")
    scan = Scan(id=None, client_id=None, target="t.com", status="complete",
                started_at="2026-06-03T10:00:00", finished_at=None)
    sid = db.insert_scan(scan)
    for i in range(n):
        db.insert_finding(Finding(id=None, scan_id=sid, host_id=None,
                                  tool="nuclei", severity="high",
                                  title=f"Finding {i}", description="",
                                  raw_json="{}", created_at=f"2026-06-03T10:{i:02d}:00"))
    return db


def test_threat_feed_starts_empty(qtbot):
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    assert feed.card_count == 0


def test_threat_feed_refresh_adds_cards(qtbot):
    db = _make_db_with_findings(5)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    assert feed.card_count == 5


def test_threat_feed_respects_limit(qtbot):
    db = _make_db_with_findings(25)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    assert feed.card_count == 20


def test_threat_feed_clear_empties(qtbot):
    db = _make_db_with_findings(3)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    feed.clear()
    assert feed.card_count == 0


def test_threat_feed_refresh_replaces_old_cards(qtbot):
    db = _make_db_with_findings(3)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    feed.refresh(db)
    assert feed.card_count == 3
```

Rewrite `tests/test_screen_dashboard.py`:
```python
from models import Scan, Finding
from db import DB
from tool_checker import TOOLS
from screens.dashboard import DashboardScreen


def _all_present():
    return {t: True for t in TOOLS}


def _critical_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    return results


def _make_db_with_data() -> DB:
    db = DB(":memory:")
    from models import Client
    from db import DB as _DB
    from models import Client, Scan, Finding
    db.insert_client(__import__('models').Client(
        id=None, name="Acme", domain="acme.com",
        firewall="none", notes="", created_at="2026-06-03T00:00:00"
    ))
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T10:00:00",
                              finished_at=None))
    db.insert_finding(Finding(id=None, scan_id=sid, host_id=None, tool="nuclei",
                              severity="high", title="XSS", description="",
                              raw_json="{}", created_at="2026-06-03T10:01:00"))
    return db


def test_dashboard_has_three_metric_cards(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert len(screen._metric_cards) == 3


def test_dashboard_metric_card_labels(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    titles = [c.title for c in screen._metric_cards]
    assert "Clients" in titles
    assert "Scans" in titles
    assert "Findings" in titles


def test_dashboard_warning_banner_hidden_when_tools_ok(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert not screen._warning_banner.isVisible()


def test_dashboard_warning_banner_shown_when_critical_missing(qtbot):
    screen = DashboardScreen(_critical_missing())
    qtbot.addWidget(screen)
    screen.show()
    assert screen._warning_banner.isVisible()


def test_dashboard_has_severity_strip(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._severity_strip is not None


def test_dashboard_has_threat_feed(qtbot):
    from screens.widgets.threat_feed import ThreatFeed
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._threat_feed is not None
    assert isinstance(screen._threat_feed, ThreatFeed)


def test_dashboard_refresh_updates_metrics(qtbot):
    db = _make_db_with_data()
    screen = DashboardScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    screen.refresh()
    # After refresh, Findings card should show >= 1
    findings_card = next(c for c in screen._metric_cards if c.title == "Findings")
    assert findings_card._value_label.text() != "0"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_widget_threat_feed.py tests/test_screen_dashboard.py::test_dashboard_has_threat_feed -v
```

- [ ] **Step 3: Create `screens/widgets/threat_feed.py`**

```python
from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QFrame, QLabel,
)

_SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#4488ff",
    "info":     "#64748b",
}
_LIMIT = 20


class ThreatFeed(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: list[QFrame] = []
        self._container = QWidget()
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._layout.addStretch()
        self.setWidget(self._container)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

    def refresh(self, db) -> None:
        self.clear()
        findings = db.query_recent_findings(limit=_LIMIT)
        for f in findings:
            color = _SEVERITY_COLORS.get(f.severity, "#64748b")
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ border-left: 3px solid {color}; "
                f"background-color: #111827; border-radius: 3px; }}"
            )
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(10, 5, 10, 5)
            card_layout.setSpacing(1)
            title_lbl = QLabel(f.title)
            title_lbl.setWordWrap(False)
            title_lbl.setStyleSheet(
                "color: #e2e8f0; font-size: 11px; font-weight: bold;"
            )
            meta_lbl = QLabel(f"{f.tool}  ·  {f.created_at[11:19]}")
            meta_lbl.setStyleSheet("color: #64748b; font-size: 9px;")
            card_layout.addWidget(title_lbl)
            card_layout.addWidget(meta_lbl)
            self._layout.insertWidget(0, card)
            self._cards.append(card)

    def clear(self) -> None:
        for card in self._cards:
            self._layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

    @property
    def card_count(self) -> int:
        return len(self._cards)
```

- [ ] **Step 4: Rewrite `screens/dashboard.py`**

```python
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
)
from tool_checker import is_critical_missing
from screens.widgets.threat_feed import ThreatFeed


class MetricCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setObjectName("panel")
        self.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(
            "color: #64748b; font-size: 11px; text-transform: uppercase;"
        )

        self._value_label = QLabel("0")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._value_label.setStyleSheet(
            "font-size: 28px; font-weight: bold; color: #e2e8f0;"
        )

        layout.addWidget(title_label)
        layout.addWidget(self._value_label)

    def set_value(self, n: int) -> None:
        self._value_label.setText(str(n))


class SeverityStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(24)
        for color, label in [
            ("#ff4444", "Critical"), ("#ff8800", "High"),
            ("#ffcc00", "Medium"), ("#4488ff", "Low"),
        ]:
            dot = QLabel(f"<span style='color:{color}'>●</span>  {label}  <b>0</b>")
            dot.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(dot)


def _placeholder_panel(label_text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(label_text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class DashboardScreen(QWidget):
    def __init__(self, tool_results: dict, db=None, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._db = db
        self._metric_cards: list[MetricCard] = []
        self._warning_banner: QLabel | None = None
        self._severity_strip: SeverityStrip | None = None
        self._threat_feed: ThreatFeed | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        self._warning_banner = QLabel("⚠  Critical tools missing — check Settings")
        self._warning_banner.setStyleSheet(
            "background-color: #3d2800; color: #ffaa00; "
            "padding: 6px 12px; border: 1px solid #ffaa00; border-radius: 4px;"
        )
        self._warning_banner.setVisible(is_critical_missing(self._tool_results))
        layout.addWidget(self._warning_banner)

        cards_row = QHBoxLayout()
        for title in ("Clients", "Scans", "Findings"):
            card = MetricCard(title)
            self._metric_cards.append(card)
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        middle_row = QHBoxLayout()
        middle_row.addWidget(
            _placeholder_panel("Attack Surface Graph\nLive in Phase 6"), stretch=1
        )
        self._threat_feed = ThreatFeed()
        middle_row.addWidget(self._threat_feed, stretch=1)
        layout.addLayout(middle_row)

        self._severity_strip = SeverityStrip()
        layout.addWidget(self._severity_strip)

        layout.addStretch()

        if self._db:
            self.refresh()

    def refresh(self) -> None:
        if not self._db:
            return
        n_clients = len(self._db.query_clients())
        null_scans = self._db.query_scans_by_client(None)
        client_scans = [
            s for cl in self._db.query_clients()
            for s in self._db.query_scans_by_client(cl.id)
        ]
        n_scans = len(null_scans) + len(client_scans)
        n_findings = len(self._db.query_recent_findings(limit=99999))

        card_map = {c.title: c for c in self._metric_cards}
        if "Clients" in card_map:
            card_map["Clients"].set_value(n_clients)
        if "Scans" in card_map:
            card_map["Scans"].set_value(n_scans)
        if "Findings" in card_map:
            card_map["Findings"].set_value(n_findings)

        self._threat_feed.refresh(self._db)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_widget_threat_feed.py tests/test_screen_dashboard.py -v
```

All must pass.

- [ ] **Step 6: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

All tests must pass.

- [ ] **Step 7: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/widgets/threat_feed.py screens/dashboard.py tests/test_widget_threat_feed.py tests/test_screen_dashboard.py
git commit -m "feat: ThreatFeed widget and live dashboard metrics

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: Settings schedule UI + ScanView.start_scan + MainWindow wiring

**Files:**
- Modify: `screens/settings.py`
- Modify: `screens/scan_view.py`
- Modify: `main_window.py`
- Append: `tests/test_screen_settings.py`
- Append: `tests/test_screen_scan_view.py`
- Append: `tests/test_main_window.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_screen_settings.py`:
```python
from db import DB
from models import Schedule


def _make_db():
    return DB(":memory:")


def test_settings_has_schedule_section(qtbot):
    screen = SettingsScreen(_all_present(), db=_make_db())
    qtbot.addWidget(screen)
    assert screen._schedule_target is not None


def test_settings_add_schedule_inserts_to_db(qtbot):
    db = _make_db()
    screen = SettingsScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    screen._schedule_target.setText("example.com")
    screen._add_schedule_btn.click()
    schedules = db.query_schedules()
    assert len(schedules) == 1
    assert schedules[0].target == "example.com"


def test_settings_add_schedule_ignores_empty_target(qtbot):
    db = _make_db()
    screen = SettingsScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    screen._schedule_target.setText("")
    screen._add_schedule_btn.click()
    assert db.query_schedules() == []
```

Append to `tests/test_screen_scan_view.py`:
```python
def test_scan_view_start_scan_sets_target(qtbot):
    from db import DB
    db = DB(":memory:")
    screen = ScanViewScreen(db=db)
    qtbot.addWidget(screen)
    screen.start_scan("example.com")
    assert screen._target_input.text() == "example.com"
```

Append to `tests/test_main_window.py`:
```python
def test_main_window_dashboard_has_db(qtbot):
    from screens.dashboard import DashboardScreen
    from db import DB
    db = DB(":memory:")
    win = MainWindow(tool_results={}, db=db)
    qtbot.addWidget(win)
    dashboard = win._stack.widget(0)
    assert isinstance(dashboard, DashboardScreen)
    assert dashboard._db is db
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_settings.py::test_settings_has_schedule_section tests/test_screen_scan_view.py::test_scan_view_start_scan_sets_target tests/test_main_window.py::test_main_window_dashboard_has_db -v
```

- [ ] **Step 3: Add schedule section to `screens/settings.py`**

Read the file first. Then:

1. Change constructor signature:
   ```python
   def __init__(self, tool_results: dict, db=None, parent=None):
   ```
   Add `self._db = db`, `self._schedule_target: QLineEdit | None = None`, `self._schedule_interval: QComboBox | None = None`, `self._add_schedule_btn: QPushButton | None = None`, `self._schedules_layout: QVBoxLayout | None = None` to `__init__`.

2. Add `QComboBox` to imports. Add after the existing tool list section in `_setup_ui`:

```python
        # Schedule section
        sched_label = QLabel("SCHEDULED SCANS")
        sched_label.setStyleSheet("color: #64748b; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(sched_label)

        sched_input_row = QHBoxLayout()
        self._schedule_target = QLineEdit()
        self._schedule_target.setPlaceholderText("Target domain (e.g. example.com)")
        self._schedule_interval = QComboBox()
        for label in ("Every 1h", "Every 4h", "Every 24h"):
            self._schedule_interval.addItem(label)
        self._schedule_interval.setCurrentIndex(2)
        self._add_schedule_btn = QPushButton("+ Add")
        self._add_schedule_btn.setFixedWidth(70)
        self._add_schedule_btn.clicked.connect(self._on_add_schedule)
        sched_input_row.addWidget(self._schedule_target, stretch=1)
        sched_input_row.addWidget(self._schedule_interval)
        sched_input_row.addWidget(self._add_schedule_btn)
        layout.addLayout(sched_input_row)

        sched_list = QFrame()
        sched_list.setObjectName("panel")
        self._schedules_layout = QVBoxLayout(sched_list)
        self._schedules_layout.setContentsMargins(8, 8, 8, 8)
        self._schedules_layout.setSpacing(4)
        layout.addWidget(sched_list)
        self._refresh_schedules()
```

3. Add methods:
```python
    def _on_add_schedule(self):
        if not self._db:
            return
        target = self._schedule_target.text().strip()
        if not target:
            return
        interval_map = {"Every 1h": 1, "Every 4h": 4, "Every 24h": 24}
        interval_h = interval_map.get(self._schedule_interval.currentText(), 24)
        from datetime import datetime, timezone
        from models import Schedule
        s = Schedule(id=None, target=target, interval_h=interval_h,
                     enabled=True, last_run=None,
                     created_at=datetime.now(timezone.utc).isoformat())
        self._db.insert_schedule(s)
        self._schedule_target.clear()
        self._refresh_schedules()

    def _refresh_schedules(self):
        if self._schedules_layout is None:
            return
        while self._schedules_layout.count():
            item = self._schedules_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not self._db:
            return
        for sched in self._db.query_schedules():
            row = QLabel(
                f"{sched.target}  ·  Every {sched.interval_h}h  ·  "
                f"{'Enabled' if sched.enabled else 'Disabled'}"
            )
            row.setStyleSheet("color: #cbd5e1; font-size: 11px;")
            self._schedules_layout.addWidget(row)
```

- [ ] **Step 4: Add `start_scan` to `screens/scan_view.py`**

Read the file. Add this public method after `_on_start_cancel`:
```python
    def start_scan(self, target: str) -> None:
        """Programmatically trigger a scan. No-op if already running or no DB."""
        if self._worker and self._worker.isRunning():
            return
        if not self._db:
            return
        self._target_input.setText(target)
        self._on_start_cancel()
```

- [ ] **Step 5: Update `main_window.py`**

Read the file. Make these changes:

1. Add `self._schedule_manager: ScheduleManager | None = None` attribute (initialized to None in `__init__`).

2. Keep a reference to DashboardScreen — change:
   ```python
   self._stack.addWidget(DashboardScreen(self._tool_results))        # 0
   ```
   To:
   ```python
   self._dashboard = DashboardScreen(self._tool_results, db=self._db)
   self._stack.addWidget(self._dashboard)                            # 0
   ```
   Also initialize `self._dashboard: DashboardScreen | None = None` in `__init__`.

3. Pass `db` to SettingsScreen — change:
   ```python
   self._stack.addWidget(SettingsScreen(self._tool_results))         # 4
   ```
   To:
   ```python
   self._stack.addWidget(SettingsScreen(self._tool_results, db=self._db))  # 4
   ```

4. Add ScheduleManager wiring after signal connections:
   ```python
   if self._db:
       from scheduler.schedule_manager import ScheduleManager
       self._schedule_manager = ScheduleManager(db=self._db, parent=self)
       self._schedule_manager.scan_due.connect(self._on_scan_due)
   ```

5. Extend `_on_scan_ready` to refresh dashboard:
   ```python
   def _on_scan_ready(self, scan_id: int):
       self._report.load_scan(scan_id)
       self._stack.setCurrentIndex(3)
       if self._dashboard:
           self._dashboard.refresh()
   ```

6. Add `_on_scan_due`:
   ```python
   def _on_scan_due(self, target: str):
       self._stack.setCurrentIndex(2)
       self._scan_view.start_scan(target)
   ```

- [ ] **Step 6: Run all modified tests**

```bash
source venv/bin/activate && pytest tests/test_screen_settings.py tests/test_screen_scan_view.py tests/test_main_window.py -v
```

All must pass.

- [ ] **Step 7: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

All tests must pass.

- [ ] **Step 8: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/settings.py screens/scan_view.py main_window.py tests/test_screen_settings.py tests/test_screen_scan_view.py tests/test_main_window.py
git commit -m "feat: schedule UI, start_scan, MainWindow wires ScheduleManager

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Notes

- ScheduleManager: `QTimer(self)` parented, stops on destroy ✓
- ThreatFeed: calls `clear()` before each `refresh()` to avoid stale cards ✓
- `start_scan`: no-op if already running or no DB ✓
- `_on_scan_due`: navigates to scan view before triggering — user can see scan progress ✓
- Dashboard `refresh()`: safe no-op when `_db is None` ✓
- Settings schedule section: guarded by `if not self._db: return` ✓
