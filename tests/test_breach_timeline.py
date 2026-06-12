import os
import pytest
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])


def _make_timeline():
    from screens.widgets.breach_timeline import BreachTimeline
    t = BreachTimeline.__new__(BreachTimeline)
    t._rows = []
    return t


def test_add_event_increments_row_count():
    t = _make_timeline()
    t.add_event({"timestamp": "2026-06-11T00:00:00Z", "event_type": "entry",
                  "source_host": "1.2.3.4", "dest_host": "server", "description": "SSH brute force"})
    assert len(t._rows) == 1


def test_add_three_events_in_order():
    t = _make_timeline()
    for et in ["entry", "lateral", "persistence"]:
        t.add_event({"timestamp": "2026-06-11T00:00:00Z", "event_type": et,
                      "source_host": "x", "dest_host": "y", "description": et})
    assert len(t._rows) == 3
    types = [r["event_type"] for r in t._rows]
    assert types == ["entry", "lateral", "persistence"]


def test_reset_clears_all_rows():
    t = _make_timeline()
    t.add_event({"timestamp": "2026-06-11T00:00:00Z", "event_type": "entry",
                  "source_host": "x", "dest_host": "y", "description": "test"})
    t._rows.clear()
    assert len(t._rows) == 0


def test_add_event_stores_event_type():
    t = _make_timeline()
    t.add_event({"timestamp": "T", "event_type": "persistence",
                  "source_host": "cron", "dest_host": "", "description": "evil cron"})
    assert t._rows[0]["event_type"] == "persistence"
