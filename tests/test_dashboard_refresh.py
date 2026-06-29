import gc
import pytest
from db import DB
from models import Finding, Scan
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


def test_dashboard_has_incidents_card(qtbot):
    db = DB(":memory:")
    screen = DashboardScreen(tool_results={}, db=db)
    qtbot.addWidget(screen)
    assert "Incidents" in {c.title for c in screen._metric_cards}


def test_refresh_updates_incident_count(qtbot):
    db = DB(":memory:")
    screen = DashboardScreen(tool_results={}, db=db)
    qtbot.addWidget(screen)
    scan_id = db.insert_scan(Scan(None, None, "t.com", "complete", _now(), _now()))
    db.insert_incident_event({"scan_id": scan_id, "event_type": "entry",
                              "description": "breach"})
    db.insert_incident_event({"scan_id": scan_id, "event_type": "lateral",
                              "description": "pivot"})
    screen.refresh()
    card_map = {c.title: c for c in screen._metric_cards}
    assert card_map["Incidents"]._value_label.text() == "2"


def test_count_incident_events_empty():
    db = DB(":memory:")
    assert db.count_incident_events() == 0
