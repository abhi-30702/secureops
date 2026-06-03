from datetime import datetime, timezone, timedelta
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
